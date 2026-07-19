"""
OpenAI Chat Completions API adapter.

Covers OpenAI, OpenRouter, and other OpenAI-compatible gateways via OPENAI_API_URL.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterable, AsyncIterator

from ..anonymizer import StreamingDeanonymizer, _apply_mappings, anonymize, deanonymize, deanon_value

_DONE = "[DONE]"


async def _anon_content_parts(content: Any, *, is_tool_output: bool) -> Any:
    if isinstance(content, str):
        return await anonymize(content, is_tool_output=is_tool_output)
    if isinstance(content, list):
        out = []
        for part in content:
            if not isinstance(part, dict):
                out.append(part)
                continue
            part = dict(part)
            if part.get("type") == "text" and isinstance(part.get("text"), str):
                part["text"] = await anonymize(part["text"], is_tool_output=is_tool_output)
            out.append(part)
        return out
    return content


async def anonymize_chat_request(body: dict) -> dict:
    """Anonymize user/tool text in an OpenAI /v1/chat/completions request."""
    messages = body.get("messages")
    if not isinstance(messages, list):
        return body

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role", "")
        if role in ("user", "tool"):
            msg["content"] = await _anon_content_parts(
                msg.get("content", ""),
                is_tool_output=True,
            )
        elif role == "system":
            # regex-only: structural prompt, not raw target data
            msg["content"] = await _anon_content_parts(
                msg.get("content", ""),
                is_tool_output=False,
            )
        # assistant: already surrogate text from prior turns — skip

    return body


def _deanon_message(message: dict) -> dict:
    content = message.get("content")
    if isinstance(content, str):
        message["content"] = deanonymize(content)

    for tc in message.get("tool_calls") or []:
        fn = tc.get("function")
        if not isinstance(fn, dict):
            continue
        args = fn.get("arguments")
        if isinstance(args, str) and args.strip():
            try:
                parsed = json.loads(args)
                fn["arguments"] = json.dumps(deanon_value(parsed))
            except json.JSONDecodeError:
                fn["arguments"] = deanonymize(args)
        elif isinstance(args, dict):
            fn["arguments"] = json.dumps(deanon_value(args))

    return message


def deanonymize_chat_response(data: dict) -> dict:
    """Deanonymize assistant text and tool call arguments in a chat completion."""
    for choice in data.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        msg = choice.get("message")
        if isinstance(msg, dict):
            choice["message"] = _deanon_message(msg)
    return data


# ── Real streaming de-anonymization ──────────────────────────────────────────

def encode_openai_sse(obj: Any) -> str:
    """Serialize one OpenAI SSE line. The [DONE] sentinel is passed as a string."""
    if obj == _DONE:
        return "data: [DONE]\n\n"
    return f"data: {json.dumps(obj)}\n\n"


async def iter_openai_sse(aiter_bytes: AsyncIterable[bytes]) -> AsyncIterator[Any]:
    """Parse an OpenAI SSE byte stream into chunk dicts and the [DONE] sentinel.

    Reassembles across arbitrary chunk boundaries. Non-JSON `data:` payloads
    other than [DONE] are skipped.
    """
    buf = ""
    data_lines: list[str] = []

    def _emit(payload: str):
        if payload == _DONE:
            return _DONE
        try:
            return json.loads(payload)
        except ValueError:
            return None

    async for chunk in aiter_bytes:
        buf += chunk.decode("utf-8", errors="replace")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.rstrip("\r")
            if line == "":
                if data_lines:
                    got = _emit("\n".join(data_lines))
                    data_lines = []
                    if got is not None:
                        yield got
                continue
            if line.startswith(":"):
                continue
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
    if data_lines:
        got = _emit("\n".join(data_lines))
        if got is not None:
            yield got


async def deanonymize_openai_stream(
    events: AsyncIterable[Any],
    mappings: list[tuple[str, str]],
) -> AsyncIterator[Any]:
    """De-anonymize an OpenAI chat-completion stream.

    Text (choices[].delta.content) is de-anonymized boundary-safe as it streams;
    tool-call arguments are buffered per (choice, tool) index and de-anonymized
    whole, emitted just before the choice's finish chunk. The [DONE] sentinel and
    all envelope fields pass through.
    """
    text: dict[int, StreamingDeanonymizer] = {}          # choice index -> deanon
    tools: dict[int, dict[int, dict]] = {}               # choice -> tool idx -> slot
    template: dict = {}

    def _mk(choices: list) -> dict:
        out = {"choices": choices}
        for k in ("id", "object", "model", "created", "system_fingerprint"):
            if k in template:
                out[k] = template[k]
        return out

    def _flush_tools(ci: int) -> dict | None:
        slots = tools.pop(ci, None)
        if not slots:
            return None
        tcs = []
        for ti in sorted(slots):
            slot = slots[ti]
            args = _apply_mappings(slot["buf"], mappings) if slot["buf"] else slot["buf"]
            fn: dict = {}
            if slot["name"] is not None:
                fn["name"] = slot["name"]
            fn["arguments"] = args
            entry: dict = {"index": ti, "function": fn}
            if slot["id"] is not None:
                entry["id"] = slot["id"]
            if slot["type"] is not None:
                entry["type"] = slot["type"]
            tcs.append(entry)
        return {"index": ci, "delta": {"tool_calls": tcs}, "finish_reason": None}

    async for ev in events:
        if ev == _DONE:
            # Defensive: flush anything not already closed by a finish_reason.
            for ci in list(text):
                tail = text.pop(ci).flush()
                if tail:
                    yield _mk([{"index": ci, "delta": {"content": tail}, "finish_reason": None}])
            for ci in list(tools):
                tc_chunk = _flush_tools(ci)
                if tc_chunk:
                    yield _mk([tc_chunk])
            yield _DONE
            continue

        for k in ("id", "object", "model", "created", "system_fingerprint"):
            if k in ev:
                template[k] = ev[k]

        for choice in ev.get("choices", []) or []:
            ci = choice.get("index", 0)
            delta = choice.get("delta", {}) or {}
            finish = choice.get("finish_reason")

            out_delta: dict = {}
            if "role" in delta:
                out_delta["role"] = delta["role"]

            content = delta.get("content")
            if isinstance(content, str) and content:
                sd = text.get(ci)
                if sd is None:
                    sd = text[ci] = StreamingDeanonymizer(mappings)
                resolved = sd.feed(content)
                if resolved:
                    out_delta["content"] = resolved

            for tc in delta.get("tool_calls") or []:
                ti = tc.get("index", 0)
                slot = tools.setdefault(ci, {}).setdefault(
                    ti, {"id": None, "type": None, "name": None, "buf": ""}
                )
                if tc.get("id"):
                    slot["id"] = tc["id"]
                if tc.get("type"):
                    slot["type"] = tc["type"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["name"] = fn["name"]
                if isinstance(fn.get("arguments"), str):
                    slot["buf"] += fn["arguments"]

            if finish is None:
                if out_delta:
                    yield _mk([{"index": ci, "delta": out_delta, "finish_reason": None}])
            else:
                # finishing: flush text tail, then tool calls, then the finish chunk
                sd = text.pop(ci, None)
                tail = sd.flush() if sd else ""
                content_piece = out_delta.get("content", "") + tail
                if content_piece:
                    yield _mk([{"index": ci, "delta": {"content": content_piece}, "finish_reason": None}])
                tc_chunk = _flush_tools(ci)
                if tc_chunk:
                    yield _mk([tc_chunk])
                yield _mk([{"index": ci, "delta": {}, "finish_reason": finish}])
