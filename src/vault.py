"""
SQLite-backed PII vault — encrypted at rest.

Every original→surrogate mapping is stored here, keyed by engagement ID.
The same original value within an engagement always maps to the same surrogate.
Different engagements are fully isolated — same IP at two clients gets different surrogates.

Security model (local-only tool):
  • The real `original` value is stored ENCRYPTED (`original_enc`, Fernet).
  • Lookups use a keyed `original_hash` (HMAC blind index) so the same value can be
    found for dedup WITHOUT keeping it in cleartext.
  • The `surrogate` is fake by construction and stays in cleartext so reverse
    lookups (deanonymization) are fast.
  • The encryption key is derived from VAULT_KEY (see src/crypto.py); the proxy
    refuses to start without it.
"""
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

_TZ_BRT = timezone(timedelta(hours=-3))

from .config import config
from . import crypto


def _conn(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or config.DATABASE_PATH
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(db_path: Path | None = None) -> None:
    conn = _conn(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS pii_vault (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement    TEXT    NOT NULL,
            entity_type   TEXT    NOT NULL,
            original_hash TEXT    NOT NULL,   -- keyed HMAC blind index (for dedup lookup)
            original_enc  TEXT    NOT NULL,   -- Fernet-encrypted real value
            surrogate     TEXT    NOT NULL,   -- fake value, safe in cleartext
            created_at    TEXT    NOT NULL,
            UNIQUE(engagement, original_hash, entity_type)
        );
        CREATE INDEX IF NOT EXISTS idx_surrogate
            ON pii_vault(engagement, surrogate);
        CREATE INDEX IF NOT EXISTS idx_orig_hash
            ON pii_vault(engagement, original_hash, entity_type);
    """)
    conn.commit()
    conn.close()


def assert_key_ok(db_path: Path | None = None) -> None:
    """Open the vault and validate VAULT_KEY against the stored canary.

    Called once at startup so a missing/wrong passphrase fails loudly and early
    instead of corrupting the surrogate space. Raises crypto.VaultKeyError.
    """
    conn = _conn(db_path)
    try:
        crypto.cipher_for(conn)   # creates salt+canary on first run, verifies after
    finally:
        conn.close()


def get_or_create(
    original: str,
    entity_type: str,
    surrogate_fn,
    engagement: str | None = None,
    db_path: Path | None = None,
) -> tuple[str, bool]:
    """Return (surrogate, is_new).

    is_new=True  → first time this value is seen; a new mapping was created.
    is_new=False → value was already in the vault; existing surrogate returned.
    """
    eng = engagement or config.ENGAGEMENT_ID
    ts  = datetime.now(_TZ_BRT).isoformat(timespec="seconds")
    conn = _conn(db_path)
    try:
        cipher = crypto.cipher_for(conn)
        ohash = cipher.blind_index(eng, entity_type, original)

        row = conn.execute(
            "SELECT surrogate FROM pii_vault "
            "WHERE engagement=? AND original_hash=? AND entity_type=?",
            (eng, ohash, entity_type),
        ).fetchone()

        if row:
            return row[0], False

        surrogate = surrogate_fn(original, entity_type)
        conn.execute(
            "INSERT INTO pii_vault "
            "(engagement, entity_type, original_hash, original_enc, surrogate, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (eng, entity_type, ohash, cipher.encrypt(original), surrogate, ts),
        )
        conn.commit()
        return surrogate, True
    finally:
        conn.close()


def get_all_mappings(
    engagement: str | None = None,
    db_path: Path | None = None,
) -> list[tuple[str, str]]:
    """Returns (surrogate, original) for the engagement, longest surrogate first.

    Decrypts each original on read. Rows that fail to decrypt are skipped so a
    single corrupt entry can never break deanonymization of the rest.
    """
    eng = engagement or config.ENGAGEMENT_ID
    conn = _conn(db_path)
    try:
        cipher = crypto.cipher_for(conn)
        rows = conn.execute(
            "SELECT surrogate, original_enc FROM pii_vault "
            "WHERE engagement=? ORDER BY LENGTH(surrogate) DESC",
            (eng,),
        ).fetchall()
        out: list[tuple[str, str]] = []
        for surrogate, original_enc in rows:
            try:
                out.append((surrogate, cipher.decrypt(original_enc)))
            except Exception:
                continue
        return out
    finally:
        conn.close()


def get_stats(db_path: Path | None = None) -> dict[str, int]:
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT entity_type, COUNT(*) FROM pii_vault "
            "WHERE engagement=? GROUP BY entity_type",
            (config.ENGAGEMENT_ID,),
        ).fetchall()
        return {r[0]: r[1] for r in rows}
    finally:
        conn.close()
