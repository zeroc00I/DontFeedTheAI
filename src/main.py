"""
pentest-proxy — transparent anonymization proxy for Claude Code.

Usage:
    export VAULT_KEY="$(openssl rand -hex 32)"   # required — encrypts the vault
    export ANTHROPIC_BASE_URL=http://localhost:8080
    export ENGAGEMENT_ID=client-acme-2026
    claude

Every API call from Claude Code passes through here. All messages and
tool results (bash outputs, file reads, grep results) are anonymized before
leaving the machine. Responses are deanonymized before Claude Code sees them.

This is a LOCAL-ONLY tool:
  • the surrogate→original vault is encrypted at rest (VAULT_KEY)
  • there is no audit/reverse-lookup endpoint exposed over HTTP
  • outbound traffic is restricted to the configured LLM upstreams (see netguard)
  • only masked surrogates ever cross the network boundary
"""
import json
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .anonymizer import anonymize, deanonymize, deanon_value
from .config import config
from . import crypto
from . import llm_detector
from .llm_detector import OllamaUnavailableError
from .vault import assert_key_ok, init_db
from .verifier import start_background_verifier
from . import timing as _timing
from . import netguard
from .hardware import detect_hardware, suggest_model, format_banner
from .providers import openai_compat
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
    unaware of it. /health and /last-activity are always allowed (liveness only,
    they expose no vault data).
    """

    async def dispatch(self, request: Request, call_next):
        secret = config.PROXY_SECRET
        if not secret:
            return await call_next(request)

        path: str = request.scope["path"]

        if path in ("/health", "/last-activity"):
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

    # Fail-closed: the vault is encrypted. Without a valid VAULT_KEY the proxy
    # must not start — otherwise it would silently create a divergent surrogate
    # space or be unable to deanonymize responses.
    try:
        assert_key_ok()
    except crypto.VaultKeyError as exc:
        log.error("=" * 60)
        log.error("FATAL: encrypted vault could not be opened")
        for line in str(exc).splitlines():
            log.error(f"  {line}")
        log.error("=" * 60)
        raise

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
    log.info(f"  vault       : {config.DATABASE_PATH}  [encrypted]")
    log.info(f"  ollama      : {config.OLLAMA_HOST}  model={config.OLLAMA_MODEL}  [{ollama_status}]")
    log.info(f"  verify      : {config.VERIFY_ENABLED}")
    log.info(f"  forwarding  : {config.ANTHROPIC_API_URL}")
    log.info(f"  allowlist   : {sorted(netguard.allowed_hosts())}")
    log.info("=" * 60)


@app.get("/health")
async def health() -> dict:
    # Intentionally minimal — never exposes vault contents, mappings, or counts.
    return {
        "status": "ok",
        "engagement": config.ENGAGEMENT_ID,
        "llm_enabled": config.LLM_ENABLED,
    }


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


# ── SSE re-emission ───────────────────────────────────────────────────────────

async def _emit_sse(data: dict):
    """
    Re-emit a complete Anthropic response as a proper SSE stream.
    We buffer the full response to deanonymize it, then re-stream it to
    preserve the typing effect Claude Code users expect.
    """
    msg_start = {
        "type": "message_start",
        "message": {
            "id":           data.get("id", ""),
            "type":         "message",
            "role":         "assistant",
            "content":      [],
            "model":        data.get("model", ""),
            "stop_reason":  None,
            "stop_sequence": None,
            "usage":        data.get("usage", {}),
        },
    }
    yield f"event: message_start\ndata: {json.dumps(msg_start)}\n\n"
    yield 'event: ping\ndata: {"type":"ping"}\n\n'

    for i, block in enumerate(data.get("content", [])):
        t = block.get("type")

        if t == "text":
            text = block.get("text", "")
            yield (
                f"event: content_block_start\n"
                f"data: {json.dumps({'type':'content_block_start','index':i,'content_block':{'type':'text','text':''}})}\n\n"
            )
            chunk_size = 32
            for j in range(0, len(text), chunk_size):
                delta = {
                    "type": "content_block_delta",
                    "index": i,
                    "delta": {"type": "text_delta", "text": text[j: j + chunk_size]},
                }
                yield f"event: content_block_delta\ndata: {json.dumps(delta)}\n\n"

        elif t == "tool_use":
            yield (
                f"event: content_block_start\n"
                f"data: {json.dumps({'type':'content_block_start','index':i,'content_block':{'type':'tool_use','id':block.get('id',''),'name':block.get('name',''),'input':{}}})}\n\n"
            )
            input_str = json.dumps(block.get("input", {}))
            chunk_size = 32
            for j in range(0, len(input_str), chunk_size):
                delta = {
                    "type": "content_block_delta",
                    "index": i,
                    "delta": {"type": "input_json_delta", "partial_json": input_str[j: j + chunk_size]},
                }
                yield f"event: content_block_delta\ndata: {json.dumps(delta)}\n\n"

        yield (
            f"event: content_block_stop\n"
            f"data: {{\"type\":\"content_block_stop\",\"index\":{i}}}\n\n"
        )

    msg_delta = {
        "type": "message_delta",
        "delta": {
            "stop_reason":   data.get("stop_reason", "end_turn"),
            "stop_sequence": None,
        },
        "usage": data.get("usage", {}),
    }
    yield f"event: message_delta\ndata: {json.dumps(msg_delta)}\n\n"
    yield 'event: message_stop\ndata: {"type":"message_stop"}\n\n'


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


def _upstream_blocked_response(*, openai_shape: bool, detail: str) -> Response:
    """Returned when netguard blocks an outbound request to a non-allowlisted host."""
    if openai_shape:
        payload = {"error": {"message": detail, "type": "upstream_blocked",
                             "code": "upstream_blocked"}}
    else:
        payload = {"type": "error", "error": {"type": "upstream_blocked", "message": detail}}
    return Response(content=json.dumps(payload), status_code=502, media_type="application/json")


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

    # Force non-streaming so we can deanonymize the complete response
    body["stream"] = False

    # ── Anthropic API ─────────────────────────────────────────────────────────
    upstream_url = f"{config.ANTHROPIC_API_URL}/v1/messages"
    try:
        netguard.assert_allowed(upstream_url)
    except netguard.UpstreamNotAllowed as exc:
        log.error(f"Outbound blocked: {exc}")
        return _upstream_blocked_response(openai_shape=False, detail=str(exc))

    t_api_start = time.perf_counter()
    async with httpx.AsyncClient(timeout=600) as client:
        resp = await client.post(upstream_url, json=body, headers=headers)
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

    if want_stream:
        return StreamingResponse(_emit_sse(data), media_type="text/event-stream")

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

    body["stream"] = False

    upstream = config.OPENAI_API_URL.rstrip("/")
    upstream_url = f"{upstream}/v1/chat/completions"
    try:
        netguard.assert_allowed(upstream_url)
    except netguard.UpstreamNotAllowed as exc:
        log.error(f"Outbound blocked: {exc}")
        return _upstream_blocked_response(openai_shape=True, detail=str(exc))

    t_api_start = time.perf_counter()
    async with httpx.AsyncClient(timeout=600) as client:
        resp = await client.post(upstream_url, json=body, headers=headers)
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

    if want_stream:
        return StreamingResponse(
            openai_compat.emit_chat_completion_sse(data),
            media_type="text/event-stream",
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
    upstream_url = f"{upstream}/{path}"

    try:
        netguard.assert_allowed(upstream_url)
    except netguard.UpstreamNotAllowed as exc:
        log.error(f"Outbound blocked: {exc}")
        return _upstream_blocked_response(openai_shape=False, detail=str(exc))

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
            params=dict(request.query_params),
        )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
    )
