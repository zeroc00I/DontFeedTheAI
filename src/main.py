"""
pentest-proxy — transparent anonymization proxy for Claude Code.

Usage:
    export ANTHROPIC_BASE_URL=http://localhost:8080
    export ENGAGEMENT_ID=client-acme-2026
    claude

Every API call from Claude Code passes through here. All messages and
tool results (bash outputs, file reads, grep results) are anonymized before
leaving the machine. Responses are deanonymized before Claude Code sees them.
"""
import json
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .anonymizer import anonymize, deanonymize, deanon_value
from .config import config
from . import llm_detector
from .llm_detector import OllamaUnavailableError
from .vault import get_all_engagements, get_all_mappings, get_stats, get_transform_log, init_db
from .verifier import start_background_verifier
from . import timing as _timing
from .hardware import detect_hardware, suggest_model, format_banner
from .providers import openai_compat
from .sse import deanonymize_sse, encode_sse, iter_sse_events
from .providers.routing import upstream_base_for_path

_TZ_BRT = timezone(timedelta(hours=-3))


class _BRTFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=_TZ_BRT)
        return dt.strftime(datefmt or "%Y-%m-%d %H:%M:%S%z")


_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(_BRTFormatter("%(asctime)s [%(name)s] %(levelname)s  %(message)s"))
logging.basicConfig(
    level=logging.INFO,
    handlers=[_handler],
)
log = logging.getLogger("cc-proxy")

app = FastAPI(title="pentest-proxy", version="1.0.0")

# Tracks the wall-clock time of the last real /v1/messages request.
# Used by the improver to decide whether to start a cycle.
_last_request_at: datetime | None = None


# ── Auth middleware ───────────────────────────────────────────────────────────

class ProxySecretMiddleware(BaseHTTPMiddleware):
    """
    If PROXY_SECRET is set, every request must include it as a URL path prefix:
      ANTHROPIC_BASE_URL=http://localhost:8080/<PROXY_SECRET>

    The middleware strips the prefix before routing, so the rest of the app is
    unaware of it. /health is always allowed (used by connect-vps.sh).
    """

    async def dispatch(self, request: Request, call_next):
        secret = config.PROXY_SECRET
        if not secret:
            return await call_next(request)

        path: str = request.scope["path"]

        if path in ("/health", "/audit", "/last-activity"):
            return await call_next(request)

        prefix = f"/{secret}"
        if path == prefix or path.startswith(prefix + "/"):
            stripped = path[len(prefix):] or "/"
            request.scope["path"] = stripped
            request.scope["raw_path"] = stripped.encode()
            return await call_next(request)

        log.warning(f"Rejected request — missing PROXY_SECRET in path: {path!r}")
        return Response(
            content=json.dumps({"error": "Forbidden — missing proxy token"}),
            status_code=403,
            media_type="application/json",
        )


app.add_middleware(ProxySecretMiddleware)


@app.on_event("startup")
async def startup() -> None:
    init_db()
    start_background_verifier()

    # Hardware detection — suggest best model and print advisory banner.
    # Runs synchronously but only reads /proc/meminfo or sysctl — near-instant.
    try:
        hw = detect_hardware()
        suggested = suggest_model(hw)
        for line in format_banner(hw, suggested, config.OLLAMA_MODEL):
            log.info(line)
    except Exception as exc:
        log.warning(f"Hardware detection skipped: {exc}")

    if config.LLM_ENABLED:
        for attempt in range(1, 4):
            try:
                await llm_detector.health_check()
                ollama_status = "OK"
                break
            except OllamaUnavailableError as exc:
                if attempt < 3:
                    log.warning(f"Ollama not ready (attempt {attempt}/3), retrying in 5s… {exc}")
                    import asyncio
                    await asyncio.sleep(5)
                else:
                    log.warning("=" * 60)
                    log.warning("Ollama unreachable at startup — running regex-only mode.")
                    log.warning(f"  {exc}")
                    log.warning("LLM detection disabled until Ollama becomes available.")
                    log.warning("=" * 60)
                    ollama_status = "unreachable (regex-only)"
    else:
        ollama_status = "disabled (LLM_ENABLED=false)"

    log.info("=" * 60)
    log.info(f"pentest-proxy started")
    log.info(f"  engagement  : {config.ENGAGEMENT_ID}")
    log.info(f"  vault       : {config.DATABASE_PATH}")
    log.info(f"  ollama      : {config.OLLAMA_HOST}  model={config.OLLAMA_MODEL}  [{ollama_status}]")
    log.info(f"  verify      : {config.VERIFY_ENABLED}")
    log.info(f"  forwarding  : {config.ANTHROPIC_API_URL}")
    log.info("=" * 60)


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "engagement": config.ENGAGEMENT_ID,
        "vault_stats": get_stats(),
        "llm_enabled": config.LLM_ENABLED,
    }


# ── Audit dashboard ───────────────────────────────────────────────────────────

_ENTITY_COLORS: dict[str, str] = {
    "IP_ADDRESS":    "#ff6b6b",
    "CIDR":          "#ff6b6b",
    "HOSTNAME":      "#ffa94d",
    "DOMAIN":        "#ffa94d",
    "USERNAME":      "#74c0fc",
    "EMAIL_ADDRESS": "#74c0fc",
    "PERSON":        "#f783ac",
    "ORGANIZATION":  "#da77f2",
    "CREDENTIAL":    "#ff4444",
    "HASH":          "#ff8c00",
    "TOKEN":         "#ff4444",
    "IDENTIFIER":    "#a9e34b",
    "PATH":          "#63e6be",
    "MAC_ADDRESS":   "#ff9f43",
    "URL":           "#54a0ff",
    "OTHER":         "#aaa",
}

_AUDIT_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:       #0b0f1a;
  --surface:  #131929;
  --surface2: #1a2236;
  --border:   #1f2d45;
  --text:     #e2e8f0;
  --muted:    #94a3b8;
  --faint:    #64748b;
  --accent:   #3b82f6;
  --green:    #22c55e;
  --red:      #f87171;
  --radius:   6px;
}

body {
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 13px;
  line-height: 1.5;
  min-height: 100vh;
}

/* ── Header ─────────────────────────────────────────────────── */
header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 0 24px;
  height: 52px;
  display: flex;
  align-items: center;
  gap: 20px;
  position: sticky;
  top: 0;
  z-index: 10;
}
.logo { font-size: 0.85em; font-weight: 600; color: var(--accent); letter-spacing: 0.5px; }
.logo span { color: var(--muted); font-weight: 400; }
.eng-pill {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 3px 12px;
  font-size: 0.8em;
  color: var(--text);
}
.eng-pill em { color: var(--accent); font-style: normal; font-weight: 600; }
.header-right { margin-left: auto; display: flex; align-items: center; gap: 16px; }
.refresh-pill { font-size: 0.75em; color: var(--faint); }
.refresh-pill span { color: var(--muted); }

/* ── Engagement tabs ─────────────────────────────────────────── */
.eng-bar {
  padding: 0 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 4px;
  height: 38px;
  overflow-x: auto;
}
.eng-bar a {
  color: var(--muted);
  text-decoration: none;
  padding: 4px 12px;
  border-radius: var(--radius);
  font-size: 0.82em;
  white-space: nowrap;
  transition: color 0.15s;
}
.eng-bar a:hover { color: var(--text); background: var(--surface2); }
.eng-bar a.active { color: var(--accent); background: var(--surface2); font-weight: 600; }

/* ── Stats strip ─────────────────────────────────────────────── */
.stats-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 12px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
}
.stat-chip {
  display: flex;
  align-items: center;
  gap: 6px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 3px 12px 3px 8px;
  font-size: 0.8em;
}
.stat-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.stat-label { color: var(--muted); }
.stat-count { color: var(--text); font-weight: 600; margin-left: 2px; }
.stat-total { background: var(--surface2); border-color: var(--accent); }
.stat-total .stat-count { color: var(--accent); }

/* ── Section header ──────────────────────────────────────────── */
.section-hd {
  padding: 16px 24px 10px;
  display: flex;
  align-items: baseline;
  gap: 10px;
}
.section-hd h2 { font-size: 0.78em; font-weight: 600; color: var(--muted);
                 letter-spacing: 0.8px; text-transform: uppercase; }
.section-hd .hint { font-size: 0.75em; color: var(--faint); }

/* ── Legend ──────────────────────────────────────────────────── */
.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  padding: 0 24px 10px;
  font-size: 0.75em;
  color: var(--muted);
}
.leg-dot { display: inline-block; width: 9px; height: 9px; border-radius: 2px;
           margin-right: 4px; vertical-align: middle; }

/* ── Tables ──────────────────────────────────────────────────── */
.table-wrap { overflow-x: auto; padding: 0 24px 24px; }
table { width: 100%; border-collapse: collapse; }
thead th {
  font-size: 0.72em;
  font-weight: 600;
  color: var(--faint);
  letter-spacing: 0.6px;
  text-transform: uppercase;
  padding: 6px 10px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
tbody td {
  padding: 7px 10px;
  border-bottom: 1px solid #151e2e;
  vertical-align: middle;
}
tbody tr:hover td { background: var(--surface2); }
tbody tr:last-child td { border-bottom: none; }

/* ── Timing table ────────────────────────────────────────────── */
.t-ts   { color: var(--faint); font-size: 0.8em; font-family: monospace; white-space: nowrap; }
.t-total { color: var(--text); font-weight: 600; font-family: monospace; white-space: nowrap; }
.t-ms   { color: var(--muted); font-family: monospace; white-space: nowrap; }
.bar-track { width: 140px; height: 6px; background: var(--surface2);
             border-radius: 3px; overflow: hidden; display: flex; flex-shrink: 0; }
.bar-seg  { height: 100%; }
.bar-llm   { background: #a78bfa; }
.bar-regex { background: #34d399; }
.bar-api   { background: #60a5fa; }
.bar-deanon{ background: #f59e0b; }
.bar-other { background: #2d3d55; }

/* ── Transformation table ────────────────────────────────────── */
.ts { color: var(--faint); font-size: 0.78em; font-family: monospace; white-space: nowrap; }
.entity-badge {
  display: inline-block;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 0.7em;
  font-weight: 700;
  letter-spacing: 0.3px;
  background: var(--surface2);
  white-space: nowrap;
}
.arrow { color: var(--faint); padding: 0 4px; }
.original  { color: #fca5a5; font-family: monospace; font-size: 0.85em;
             max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.surrogate { color: #86efac; font-family: monospace; font-size: 0.85em;
             max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.badge-new    { display: inline-block; padding: 1px 7px; border-radius: 10px;
                font-size: 0.7em; font-weight: 700; background: #052e16; color: #4ade80; }
.badge-cached { display: inline-block; padding: 1px 7px; border-radius: 10px;
                font-size: 0.7em; background: var(--surface2); color: var(--faint); }
tr.new-row td:first-child { border-left: 2px solid #22c55e; padding-left: 8px; }
tr.cached-row td:first-child { border-left: 2px solid var(--surface2); padding-left: 8px; }

/* ── Empty state ─────────────────────────────────────────────── */
.empty { color: var(--faint); text-align: center; padding: 48px 24px;
         font-size: 0.95em; line-height: 2; }
.empty strong { color: var(--muted); }
"""

_AUDIT_JS = """
let t = 15;
const el = document.getElementById('cd');
setInterval(() => {
  t--;
  if (el) el.textContent = t + 's';
  if (t <= 0) location.reload();
}, 1000);
"""


def _render_timing_rows(timings: list[dict]) -> str:
    if not timings:
        return '<tr><td colspan="7" class="empty" style="padding:30px">No requests recorded yet.</td></tr>'
    rows = []
    for t in timings:
        total = t.get("total_ms", 0) or 1  # avoid div-by-zero
        llm    = t.get("llm_ms",    0)
        regex  = t.get("regex_ms",  0)
        api    = t.get("api_ms",    0)
        deanon = t.get("deanon_ms", 0)
        other  = max(0, total - llm - regex - api - deanon)
        # pct widths for stacked bar
        def pct(v): return f"{min(100, v / total * 100):.1f}%"
        bar = (
            f'<div class="bar-track">'
            f'<div class="bar-seg bar-llm"    style="width:{pct(llm)}"></div>'
            f'<div class="bar-seg bar-regex"  style="width:{pct(regex)}"></div>'
            f'<div class="bar-seg bar-api"    style="width:{pct(api)}"></div>'
            f'<div class="bar-seg bar-deanon" style="width:{pct(deanon)}"></div>'
            f'<div class="bar-seg bar-other"  style="width:{pct(other)}"></div>'
            f'</div>'
        )
        rows.append(
            f'<tr>'
            f'<td class="ts">{t.get("ts","")}</td>'
            f'<td class="ms-total">{total:.0f} ms</td>'
            f'<td class="ms">{llm:.0f}</td>'
            f'<td class="ms">{regex:.0f}</td>'
            f'<td class="ms">{api:.0f}</td>'
            f'<td class="ms">{deanon:.0f}</td>'
            f'<td class="bar-cell"><div class="bar-wrap">{bar}</div></td>'
            f'</tr>'
        )
    return "\n".join(rows)


def _render_audit(eng: str, entries: list[dict], all_engs: list[str],
                  stats: dict[str, int], timings: list[dict] | None = None) -> str:
    entity_color_styles = "\n".join(
        f'.et-{k.replace("_","").lower()} {{ color: {v}; border-color: {v}33; }}'
        for k, v in _ENTITY_COLORS.items()
    )

    total = sum(stats.values())
    new_count = sum(1 for e in entries if e["is_new"])

    # Stats chips
    _fallback = "#94a3b8"
    total_chip = '<div class="stat-chip stat-total"><span class="stat-label">total</span><span class="stat-count">{}</span></div>'.format(total)
    type_chips = "".join(
        '<div class="stat-chip">'
        '<span class="stat-dot" style="background:{};"></span>'
        '<span class="stat-label">{}</span>'
        '<span class="stat-count">{}</span>'
        '</div>'.format(_ENTITY_COLORS.get(k, _fallback), k.replace("_", " ").lower(), v)
        for k, v in sorted(stats.items(), key=lambda x: -x[1])
    ) if stats else '<span style="color:var(--faint);font-size:0.8em">no data yet — make a request through the proxy</span>'

    # Engagement tabs
    eng_tabs = "".join(
        '<a href="/audit?eng={e}" class="{cls}">{e}</a>'.format(
            e=e, cls="active" if e == eng else ""
        )
        for e in all_engs
    ) if all_engs else '<span style="color:var(--faint);font-size:0.8em">none</span>'

    # Timing table rows
    timing_rows = _render_timing_rows(timings or [])

    # Transformation rows
    if not entries:
        rows_html = (
            '<tr><td colspan="5" class="empty">'
            '<strong>No transformations recorded yet.</strong><br>'
            'Start a Claude Code session via <code>make connect</code> to see live data.'
            '</td></tr>'
        )
    else:
        rows = []
        for e in entries:
            et = e["entity_type"]
            color = _ENTITY_COLORS.get(et, _fallback)
            badge = "new" if e["is_new"] else "cached"
            rows.append(
                f'<tr class="{badge}-row">'
                f'<td class="ts">{e["ts"]}</td>'
                f'<td><span class="entity-badge et-{et.replace("_","").lower()}" '
                f'style="color:{color};border:1px solid {color}33">{et}</span></td>'
                f'<td class="original" title="{e["original"]}">{e["original"]}</td>'
                f'<td class="arrow">→</td>'
                f'<td class="surrogate" title="{e["surrogate"]}">{e["surrogate"]}</td>'
                f'<td><span class="badge-{badge}">{"NEW" if e["is_new"] else "cached"}</span></td>'
                f'</tr>'
            )
        rows_html = "\n".join(rows)

    n_timing = len(timings or [])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit — {eng}</title>
<style>
{_AUDIT_CSS}
{entity_color_styles}
</style>
</head>
<body>

<header>
  <span class="logo">&#128274; LLM <span>Anonymization</span></span>
  <div class="eng-pill">engagement: <em>{eng}</em></div>
  <div class="header-right">
    <span class="refresh-pill">refresh in <span id="cd">15</span>s</span>
  </div>
</header>

{('<div class="eng-bar">' + eng_tabs + '</div>') if len(all_engs) > 1 else ''}

<div class="stats-strip">
  {total_chip}
  {type_chips}
</div>

<div class="section-hd">
  <h2>Request Timing</h2>
  <span class="hint">last {n_timing} requests &mdash; resets on restart</span>
</div>
<div class="legend">
  <span><span class="leg-dot" style="background:#a78bfa"></span>LLM</span>
  <span><span class="leg-dot" style="background:#34d399"></span>Regex</span>
  <span><span class="leg-dot" style="background:#60a5fa"></span>API</span>
  <span><span class="leg-dot" style="background:#f59e0b"></span>Deanon</span>
</div>
<div class="table-wrap">
<table>
<thead><tr>
  <th>Time</th><th>Total</th>
  <th style="color:#a78bfa">LLM</th>
  <th style="color:#34d399">Regex</th>
  <th style="color:#60a5fa">API</th>
  <th style="color:#f59e0b">Deanon</th>
  <th>Breakdown</th>
</tr></thead>
<tbody>{timing_rows}</tbody>
</table>
</div>

<div class="section-hd">
  <h2>Transformation Log</h2>
  <span class="hint">{len(entries)} mappings &mdash; {new_count} new</span>
</div>
<div class="table-wrap">
<table>
<thead><tr>
  <th>Timestamp</th><th>Type</th>
  <th>Original</th><th></th><th>Surrogate</th><th>Status</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>

<script>{_AUDIT_JS}</script>
</body>
</html>"""


@app.get("/audit", response_class=HTMLResponse)
async def audit_dashboard(
    eng: str = Query(default=None, description="Engagement ID to view"),
) -> HTMLResponse:
    """Transformation audit log — shows timing breakdown + original→surrogate history."""
    engagement = eng or config.ENGAGEMENT_ID
    entries    = get_transform_log(engagement=engagement, limit=500)
    all_engs   = get_all_engagements()
    stats      = get_stats()
    timings    = _timing.get_recent(50)
    if not all_engs:
        all_engs = [engagement]
    html = _render_audit(engagement, entries, all_engs, stats, timings)
    return HTMLResponse(content=html)


# ── Request traversal helpers ─────────────────────────────────────────────────

async def _anon_block(block: dict, is_tool_output: bool = False) -> dict:
    t = block.get("type")
    if t == "text":
        # text inside a tool_result is raw tool output — use LLM
        block["text"] = await anonymize(block.get("text", ""), is_tool_output=is_tool_output)
    elif t == "tool_result":
        # tool_result content is always the real sensitive data — always use LLM
        c = block.get("content", "")
        if isinstance(c, str):
            block["content"] = await anonymize(c, is_tool_output=True)
        elif isinstance(c, list):
            block["content"] = [await _anon_block(b, is_tool_output=True) for b in c]
    return block


async def _anon_message(msg: dict) -> dict:
    role = msg.get("role", "")
    c = msg.get("content", "")
    # User messages (text typed by the pentester) may contain company names,
    # person names, CPF/CNPJ — enable LLM so contextual entities are caught.
    # Assistant messages are skipped (they contain surrogate text already).
    use_llm = role == "user"
    if isinstance(c, str):
        msg["content"] = await anonymize(c, is_tool_output=use_llm)
    elif isinstance(c, list):
        msg["content"] = [await _anon_block(b, is_tool_output=use_llm) for b in c]
    return msg


async def _anon_request(body: dict) -> dict:
    """Anonymize all text content in a /v1/messages request body."""
    if "messages" in body:
        body["messages"] = [await _anon_message(m) for m in body["messages"]]

    sys_prompt = body.get("system")
    if isinstance(sys_prompt, str):
        body["system"] = await anonymize(sys_prompt, is_tool_output=False)
    elif isinstance(sys_prompt, list):
        body["system"] = [await _anon_block(b, is_tool_output=False) for b in sys_prompt]

    return body


def _deanon_response(data: dict) -> dict:
    """Deanonymize all text and tool_use inputs in an Anthropic response."""
    for block in data.get("content", []):
        t = block.get("type")
        if t == "text":
            block["text"] = deanonymize(block.get("text", ""))
        elif t == "tool_use":
            # Deanonymize tool inputs so Claude Code executes commands with real values
            block["input"] = deanon_value(block.get("input", {}))
    return data


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/last-activity")
async def last_activity() -> dict:
    """Return when the proxy last handled a real /v1/messages request."""
    global _last_request_at
    if _last_request_at is None:
        return {"last_request_at": None, "idle_seconds": None}
    idle = (datetime.now(timezone.utc) - _last_request_at).total_seconds()
    return {
        "last_request_at": _last_request_at.isoformat(),
        "idle_seconds": round(idle),
    }


def _filter_forward_headers(request: Request) -> dict[str, str]:
    return {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }


def _ollama_unavailable_response(*, openai_shape: bool) -> Response:
    message = (
        "LLM anonymization layer (Ollama) is unreachable. "
        "Request blocked to prevent unredacted data from reaching the upstream API. "
        "Start Ollama and ensure the model is loaded, then retry."
    )
    if openai_shape:
        payload = {
            "error": {
                "message": message,
                "type": "anonymizer_unavailable",
                "code": "anonymizer_unavailable",
            }
        }
    else:
        payload = {
            "type": "error",
            "error": {"type": "anonymizer_unavailable", "message": message},
        }
    return Response(
        content=json.dumps(payload),
        status_code=503,
        media_type="application/json",
    )


@app.post("/v1/messages")
async def proxy_messages(request: Request) -> Response:
    global _last_request_at
    _last_request_at = datetime.now(timezone.utc)
    req_start = time.perf_counter()
    _timing.reset()

    body = await request.json()
    headers = _filter_forward_headers(request)

    want_stream = body.get("stream", False)
    model = body.get("model", "?")
    n_msgs = len(body.get("messages", []))
    log.info(f"→ model={model}  msgs={n_msgs}  stream={want_stream}")

    # ── Anonymize ─────────────────────────────────────────────────────────────
    t_anon_start = time.perf_counter()
    try:
        body = await _anon_request(body)
    except OllamaUnavailableError as exc:
        log.error(f"Ollama unavailable during anonymization — blocking request: {exc}")
        return _ollama_unavailable_response(openai_shape=False)
    anon_ms = (time.perf_counter() - t_anon_start) * 1000

    # Snapshot LLM + regex breakdown accumulated inside anonymize()
    anon_snap = _timing.snapshot()

    # ── Streaming path: forward stream=True and de-anonymize the SSE inline ────
    # Surrogates are resolved as tokens arrive (boundary-safe for text/thinking;
    # tool_use inputs buffered per block). Real streaming restores time-to-first-
    # token instead of buffering the whole completion before the user sees output.
    if want_stream:
        body["stream"] = True
        mappings = get_all_mappings()   # snapshot the vault for the whole response
        upstream = f"{config.ANTHROPIC_API_URL}/v1/messages"

        async def _stream_deanonymized():
            try:
                async with httpx.AsyncClient(timeout=600) as client:
                    async with client.stream(
                        "POST", upstream, json=body, headers=headers,
                    ) as resp:
                        if resp.status_code != 200:
                            err = (await resp.aread()).decode("utf-8", "replace")[:500]
                            log.warning(f"← Anthropic {resp.status_code} (stream): {err[:200]}")
                            yield encode_sse("error", {
                                "type": "error",
                                "error": {"type": "api_error", "message": err},
                            })
                            return
                        events = iter_sse_events(resp.aiter_bytes())
                        async for out_ev in deanonymize_sse(events, mappings):
                            yield encode_sse(out_ev.get("type", ""), out_ev)
            finally:
                total_ms = (time.perf_counter() - req_start) * 1000
                _timing.record({
                    "ts":        datetime.now(_TZ_BRT).strftime("%H:%M:%S"),
                    "model":     model,
                    "total_ms":  round(total_ms, 1),
                    "anon_ms":   round(anon_ms, 1),
                    "llm_ms":    anon_snap["llm_ms"],
                    "regex_ms":  anon_snap["regex_ms"],
                    # de-anonymization is folded into the stream, so its cost is
                    # not separable; attribute the post-anon time to the round-trip.
                    "api_ms":    round(max(0.0, total_ms - anon_ms), 1),
                    "deanon_ms": 0.0,
                })

        log.info("← streaming (deanonymized inline)")
        return StreamingResponse(_stream_deanonymized(), media_type="text/event-stream")

    # ── Non-streaming path: buffer the full response, deanonymize, return JSON ─
    body["stream"] = False

    # ── Anthropic API ─────────────────────────────────────────────────────────
    t_api_start = time.perf_counter()
    async with httpx.AsyncClient(timeout=600) as client:
        resp = await client.post(
            f"{config.ANTHROPIC_API_URL}/v1/messages",
            json=body,
            headers=headers,
        )
    api_ms = (time.perf_counter() - t_api_start) * 1000

    if resp.status_code != 200:
        log.warning(f"← Anthropic {resp.status_code}: {resp.text[:200]}")
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type="application/json",
        )

    # ── Deanonymize ───────────────────────────────────────────────────────────
    t_deanon_start = time.perf_counter()
    data = resp.json()
    data = _deanon_response(data)
    deanon_ms = (time.perf_counter() - t_deanon_start) * 1000

    total_ms = (time.perf_counter() - req_start) * 1000

    log.info(
        f"← ok  stop_reason={data.get('stop_reason')}"
        f"  total={total_ms:.0f}ms"
        f"  anon={anon_ms:.0f}ms (llm={anon_snap['llm_ms']:.0f} regex={anon_snap['regex_ms']:.0f})"
        f"  api={api_ms:.0f}ms  deanon={deanon_ms:.0f}ms"
    )

    # ── Record timing ─────────────────────────────────────────────────────────
    _timing.record({
        "ts":        datetime.now(_TZ_BRT).strftime("%H:%M:%S"),
        "model":     model,
        "total_ms":  round(total_ms, 1),
        "anon_ms":   round(anon_ms, 1),
        "llm_ms":    anon_snap["llm_ms"],
        "regex_ms":  anon_snap["regex_ms"],
        "api_ms":    round(api_ms, 1),
        "deanon_ms": round(deanon_ms, 1),
    })

    return Response(
        content=json.dumps(data),
        status_code=200,
        media_type="application/json",
    )


@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request) -> Response:
    """OpenAI-compatible chat completions (OpenAI, OpenRouter, local gateways)."""
    global _last_request_at
    _last_request_at = datetime.now(timezone.utc)
    req_start = time.perf_counter()
    _timing.reset()

    body = await request.json()
    headers = _filter_forward_headers(request)

    want_stream = body.get("stream", False)
    model = body.get("model", "?")
    n_msgs = len(body.get("messages", []))
    log.info(f"→ [openai] model={model}  msgs={n_msgs}  stream={want_stream}")

    t_anon_start = time.perf_counter()
    try:
        body = await openai_compat.anonymize_chat_request(body)
    except OllamaUnavailableError as exc:
        log.error(f"Ollama unavailable during anonymization — blocking request: {exc}")
        return _ollama_unavailable_response(openai_shape=True)
    anon_ms = (time.perf_counter() - t_anon_start) * 1000
    anon_snap = _timing.snapshot()

    upstream = config.OPENAI_API_URL.rstrip("/")

    # ── Streaming path: forward stream=True and de-anonymize the SSE inline ────
    if want_stream:
        body["stream"] = True
        mappings = get_all_mappings()

        async def _stream_openai_deanonymized():
            try:
                async with httpx.AsyncClient(timeout=600) as client:
                    async with client.stream(
                        "POST", f"{upstream}/v1/chat/completions", json=body, headers=headers,
                    ) as resp:
                        if resp.status_code != 200:
                            err = (await resp.aread()).decode("utf-8", "replace")[:500]
                            log.warning(f"← [openai] {resp.status_code} (stream): {err[:200]}")
                            yield openai_compat.encode_openai_sse(
                                {"error": {"message": err, "type": "api_error"}}
                            )
                            yield openai_compat.encode_openai_sse("[DONE]")
                            return
                        events = openai_compat.iter_openai_sse(resp.aiter_bytes())
                        async for out in openai_compat.deanonymize_openai_stream(events, mappings):
                            yield openai_compat.encode_openai_sse(out)
            finally:
                total_ms = (time.perf_counter() - req_start) * 1000
                _timing.record({
                    "ts":        datetime.now(_TZ_BRT).strftime("%H:%M:%S"),
                    "model":     model,
                    "total_ms":  round(total_ms, 1),
                    "anon_ms":   round(anon_ms, 1),
                    "llm_ms":    anon_snap["llm_ms"],
                    "regex_ms":  anon_snap["regex_ms"],
                    "api_ms":    round(max(0.0, total_ms - anon_ms), 1),
                    "deanon_ms": 0.0,
                })

        log.info("← [openai] streaming (deanonymized inline)")
        return StreamingResponse(_stream_openai_deanonymized(), media_type="text/event-stream")

    # ── Non-streaming path: buffer the full response, deanonymize, return JSON ─
    body["stream"] = False
    t_api_start = time.perf_counter()
    async with httpx.AsyncClient(timeout=600) as client:
        resp = await client.post(
            f"{upstream}/v1/chat/completions",
            json=body,
            headers=headers,
        )
    api_ms = (time.perf_counter() - t_api_start) * 1000

    if resp.status_code != 200:
        log.warning(f"← [openai] {resp.status_code}: {resp.text[:200]}")
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type="application/json",
        )

    t_deanon_start = time.perf_counter()
    data = resp.json()
    data = openai_compat.deanonymize_chat_response(data)
    deanon_ms = (time.perf_counter() - t_deanon_start) * 1000

    total_ms = (time.perf_counter() - req_start) * 1000
    log.info(
        f"← [openai] ok  total={total_ms:.0f}ms"
        f"  anon={anon_ms:.0f}ms (llm={anon_snap['llm_ms']:.0f} regex={anon_snap['regex_ms']:.0f})"
        f"  api={api_ms:.0f}ms  deanon={deanon_ms:.0f}ms"
    )

    return Response(
        content=json.dumps(data),
        status_code=200,
        media_type="application/json",
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def proxy_catchall(request: Request, path: str) -> Response:
    """Pass-through for other upstream endpoints (/v1/models, embeddings, …)."""
    headers = _filter_forward_headers(request)
    body = await request.body()
    upstream = upstream_base_for_path(path)

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.request(
            method=request.method,
            url=f"{upstream}/{path}",
            headers=headers,
            content=body,
            params=dict(request.query_params),
        )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
    )
