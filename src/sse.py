"""
Streaming SSE de-anonymization.

Anthropic streams a response as Server-Sent Events. This module transforms the
parsed event stream so surrogates are turned back into their originals *as they
stream*, without ever emitting a partial/undeanonymized surrogate:

  - text / thinking deltas  → boundary-safe incremental de-anonymization
    (a surrogate split across two deltas is held back until complete).
  - tool_use input_json     → buffered per block and de-anonymized at block
    stop, because Claude Code executes the tool call with the REAL values and
    the JSON must be resolved in one piece.
  - every other event       → passed through untouched.

The transform operates on parsed event dicts (the SSE `data` payloads) so it is
independently testable; byte-level SSE parsing/encoding lives in main.py.
"""
from __future__ import annotations

import json
from typing import AsyncIterable, AsyncIterator

from .anonymizer import StreamingDeanonymizer, _apply_mappings


def encode_sse(event: str, data: dict) -> str:
    """Serialize one SSE event. The `event:` name mirrors the payload's type."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def iter_sse_events(aiter_bytes: AsyncIterable[bytes]) -> AsyncIterator[dict]:
    """Parse a raw SSE byte stream into decoded `data:` JSON payloads.

    Reassembles events across arbitrary chunk boundaries. `event:`/`id:`/comment
    lines are ignored — the payload's own `type` field carries the event kind.
    """
    buf = ""
    data_lines: list[str] = []
    async for chunk in aiter_bytes:
        buf += chunk.decode("utf-8", errors="replace")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.rstrip("\r")
            if line == "":
                if data_lines:
                    payload = "\n".join(data_lines)
                    data_lines = []
                    try:
                        yield json.loads(payload)
                    except ValueError:
                        pass
                continue
            if line.startswith(":"):
                continue
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
    if data_lines:
        try:
            yield json.loads("\n".join(data_lines))
        except ValueError:
            pass


async def deanonymize_sse(
    events: AsyncIterable[dict],
    mappings: list[tuple[str, str]],
) -> AsyncIterator[dict]:
    """Yield de-anonymized copies of the incoming Anthropic SSE event dicts."""
    # index -> (block_type, StreamingDeanonymizer) for text/thinking blocks
    text_blocks: dict[int, tuple[str, StreamingDeanonymizer]] = {}
    # index -> accumulated partial_json for tool_use blocks
    tool_buffers: dict[int, str] = {}

    def _text_delta(index: int, block_type: str, text: str) -> dict:
        field = "thinking" if block_type == "thinking" else "text"
        return {
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": f"{field}_delta", field: text},
        }

    async for ev in events:
        etype = ev.get("type")

        if etype == "content_block_start":
            idx = ev.get("index")
            btype = ev.get("content_block", {}).get("type")
            if btype in ("text", "thinking"):
                text_blocks[idx] = (btype, StreamingDeanonymizer(mappings))
            elif btype == "tool_use":
                tool_buffers[idx] = ""
            yield ev

        elif etype == "content_block_delta":
            idx = ev.get("index")
            delta = ev.get("delta", {})
            dtype = delta.get("type")

            if dtype in ("text_delta", "thinking_delta") and idx in text_blocks:
                btype, deanon = text_blocks[idx]
                field = "thinking" if btype == "thinking" else "text"
                out = deanon.feed(delta.get(field, ""))
                if out:
                    yield _text_delta(idx, btype, out)
                # nothing safe to emit yet → swallow this delta

            elif dtype == "input_json_delta" and idx in tool_buffers:
                tool_buffers[idx] += delta.get("partial_json", "")
                # buffered; emitted whole at content_block_stop

            else:
                yield ev  # signature_delta and anything unrecognised

        elif etype == "content_block_stop":
            idx = ev.get("index")
            if idx in text_blocks:
                btype, deanon = text_blocks.pop(idx)
                tail = deanon.flush()
                if tail:
                    yield _text_delta(idx, btype, tail)
                yield ev
            elif idx in tool_buffers:
                raw = tool_buffers.pop(idx)
                resolved = _apply_mappings(raw, mappings) if raw else raw
                if resolved:
                    yield {
                        "type": "content_block_delta",
                        "index": idx,
                        "delta": {"type": "input_json_delta", "partial_json": resolved},
                    }
                yield ev
            else:
                yield ev

        else:
            yield ev
