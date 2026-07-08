"""
Background verifier — detects anonymization failures in real proxy traffic.

During live proxy use, anonymize() calls record_traffic() after each
anonymization. A background task periodically runs the Ollama judge over
unverified records and writes failures to the verify.db failures table.

The feedback loop reads these failures to continuously improve the system prompt.

Design goals:
  • Non-blocking — never slows down the proxy's main response path
  • Local-only — original text stored only in local SQLite, never sent anywhere
  • Engagement-isolated — each engagement has its own records
"""
import asyncio
import json
import logging
import sqlite3
import time
from pathlib import Path

import httpx

from .config import config
from . import crypto

log = logging.getLogger("cc-proxy.verifier")

# ── Database ──────────────────────────────────────────────────────────────────

def _db_path() -> Path:
    return config.DATA_DIR / "verify.db"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db():
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS traffic (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement    TEXT    NOT NULL,
                recorded_at   REAL    NOT NULL,
                original_enc  TEXT    NOT NULL,   -- Fernet-encrypted real text
                anonymized    TEXT    NOT NULL,   -- surrogate-only, safe in cleartext
                verified      INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS failures (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                traffic_id  INTEGER REFERENCES traffic(id),
                engagement  TEXT    NOT NULL,
                found_at    REAL    NOT NULL,
                leaked_text TEXT    NOT NULL,
                concern     TEXT    NOT NULL DEFAULT '',
                used_for_improvement INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_verified ON traffic(verified, engagement);
            CREATE INDEX IF NOT EXISTS idx_failures_used    ON failures(used_for_improvement);
        """)


# ── Traffic recording ─────────────────────────────────────────────────────────

# Minimum length to bother recording — very short texts have almost no PII risk
_MIN_RECORD_LEN = 40


def record_traffic(original: str, anonymized: str) -> None:
    """
    Synchronously log one anonymization event.
    Called from anonymizer.py after every tool-output anonymization.
    Only records if content is long enough to be interesting.
    """
    if not config.VERIFY_ENABLED:
        return
    if not original or len(original) < _MIN_RECORD_LEN:
        return
    try:
        _init_db()
        with _get_conn() as conn:
            original_enc = crypto.cipher_for(conn).encrypt(original)
            conn.execute(
                "INSERT INTO traffic (engagement, recorded_at, original_enc, anonymized) VALUES (?,?,?,?)",
                (config.ENGAGEMENT_ID, time.time(), original_enc, anonymized),
            )
    except Exception as exc:
        log.debug(f"record_traffic failed: {exc}")


# ── Judge prompt ──────────────────────────────────────────────────────────────

_JUDGE_PROMPT = """\
You are a red-team reviewer. You received text that was processed by an
anonymization system to hide all information identifying the real pentest target.

Your task: find any value that STILL reveals the real target organisation,
its infrastructure, or its people.

SURROGATE PATTERNS already in place — do NOT flag these:
  - IPs in ranges 10.200.x.x, 10.201.x.x, 172.28.x.x
  - Domains ending .pentest.local or .pentest
  - Emails ending @example.pentest
  - Tokens like [CRED_XXXXXXXX], [TOKEN_XXX], [REDACTED_XXX]
  - Usernames like user_xxxx, svc_xxxx
  - Hostnames like srv-NNNN, host-NNNN, dc-NNNN
  - Fake company names that look like placeholders

FLAG if you still see:
  - A real company or organisation name
  - A real person name (first + last, not user_xxxx format)
  - A real IP, CIDR, or hostname not matching the surrogate patterns above
  - A real domain, not matching .pentest.local
  - A real credential, password, hash, JWT, or API token
  - Any value that uniquely identifies the real engagement target

Return ONLY valid JSON, no explanation, no markdown:
{"leaked": [{"text": "<exact substring from the text>", "concern": "<why sensitive>"}]}

If nothing real leaked: {"leaked": []}
"""


async def _judge_chunk(client: httpx.AsyncClient, text: str) -> list[dict]:
    """Run the judge LLM on one text chunk. Returns [{text, concern}] or []."""
    try:
        resp = await client.post(
            f"{config.OLLAMA_HOST}/api/chat",
            json={
                "model": config.OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": _JUDGE_PROMPT},
                    {"role": "user",   "content": text},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0, "think": False,
                            "num_thread": config.OLLAMA_NUM_THREADS},
            },
            timeout=config.OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        raw = resp.json().get("message", {}).get("content", "")
        import re
        cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        data = json.loads(cleaned)
        return [item for item in data.get("leaked", [])
                if isinstance(item, dict) and item.get("text", "").strip()]
    except Exception as exc:
        log.debug(f"Judge call failed: {exc}")
        return []


# ── Background verification loop ──────────────────────────────────────────────

_VERIFY_INTERVAL_S = 120    # run verifier every 2 minutes
_VERIFY_BATCH      = 10     # process at most N records per run
_verifier_task: asyncio.Task | None = None


async def _verify_loop():
    """Background asyncio task — runs judge over unverified traffic records."""
    log.info("Background verifier started")
    while True:
        await asyncio.sleep(_VERIFY_INTERVAL_S)
        try:
            await _verify_batch()
        except Exception as exc:
            log.debug(f"Verify batch error: {exc}")


async def _verify_batch():
    """Process up to _VERIFY_BATCH unverified records."""
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT id, anonymized FROM traffic WHERE verified=0 ORDER BY recorded_at LIMIT ?",
            (_VERIFY_BATCH,),
        ).fetchall()
    except Exception:
        return

    if not rows:
        return

    log.debug(f"Verifying {len(rows)} traffic records…")
    async with httpx.AsyncClient(timeout=config.OLLAMA_TIMEOUT + 10) as client:
        for row in rows:
            tid = row["id"]
            anonymized = row["anonymized"]
            leaks = await _judge_chunk(client, anonymized[:2000])

            with _get_conn() as conn:
                conn.execute("UPDATE traffic SET verified=1 WHERE id=?", (tid,))
                for leak in leaks:
                    conn.execute(
                        "INSERT INTO failures (traffic_id, engagement, found_at, leaked_text, concern)"
                        " VALUES (?,?,?,?,?)",
                        (tid, config.ENGAGEMENT_ID, time.time(),
                         leak.get("text", ""), leak.get("concern", "")),
                    )

            if leaks:
                log.warning(
                    f"[verifier] {len(leaks)} leak(s) survived anonymization: "
                    + ", ".join(repr(l.get("text", "")) for l in leaks[:3])
                )


def start_background_verifier(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Start the background verifier task. Call once at proxy startup."""
    global _verifier_task
    if not config.VERIFY_ENABLED:
        return
    _init_db()
    try:
        _verifier_task = asyncio.get_event_loop().create_task(_verify_loop())
        log.info("Background verifier scheduled")
    except RuntimeError:
        log.debug("Could not start background verifier (no running event loop)")


# ── Failure queries (used by feedback loop) ───────────────────────────────────

def get_pending_failures(limit: int = 50) -> list[dict]:
    """Return failures not yet used for improvement, newest first."""
    try:
        _init_db()
        conn = _get_conn()
        cipher = crypto.cipher_for(conn)
        rows = conn.execute(
            "SELECT f.id, f.leaked_text, f.concern, t.original_enc, t.anonymized "
            "FROM failures f JOIN traffic t ON f.traffic_id = t.id "
            "WHERE f.used_for_improvement=0 ORDER BY f.found_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            enc = d.pop("original_enc", "")
            try:
                d["original"] = cipher.decrypt(enc) if enc else ""
            except Exception:
                d["original"] = ""
            out.append(d)
        return out
    except Exception as exc:
        log.debug(f"get_pending_failures failed: {exc}")
        return []


def mark_failures_used(failure_ids: list[int]) -> None:
    """Mark failure records as consumed by an improvement round."""
    if not failure_ids:
        return
    try:
        with _get_conn() as conn:
            conn.executemany(
                "UPDATE failures SET used_for_improvement=1 WHERE id=?",
                [(fid,) for fid in failure_ids],
            )
    except Exception as exc:
        log.debug(f"mark_failures_used failed: {exc}")
