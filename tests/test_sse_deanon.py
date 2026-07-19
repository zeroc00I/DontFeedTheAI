"""
Unit tests for the streaming SSE de-anonymization transform.

Anthropic streams a response as parsed SSE events. The transform must:
  - de-anonymize text/thinking deltas boundary-safely (surrogate may split
    across two deltas) so a partial surrogate is never emitted,
  - buffer tool_use input_json fragments and emit the de-anonymized input at
    block stop (Claude Code executes tool calls with REAL values),
  - pass all other events (message_start, ping, message_stop, ...) through.
"""
import json

import pytest

from src.sse import deanonymize_sse, encode_sse, iter_sse_events

MAPPINGS = [("SRV-1042", "10.10.14.22"), ("USR-77", "j.martins")]


async def _aiter(events):
    for e in events:
        yield e


async def _collect(events, mappings):
    return [e async for e in deanonymize_sse(_aiter(events), mappings)]


def _text_of(out):
    return "".join(
        e["delta"]["text"]
        for e in out
        if e.get("type") == "content_block_delta"
        and e["delta"].get("type") == "text_delta"
    )


@pytest.mark.asyncio
async def test_text_delta_split_across_events_is_deanonymized():
    events = [
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "text_delta", "text": "host SRV-10"}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "text_delta", "text": "42 is up"}},
        {"type": "content_block_stop", "index": 0},
    ]
    out = await _collect(events, MAPPINGS)
    assert _text_of(out) == "host 10.10.14.22 is up"
    assert "SRV-1042" not in _text_of(out)


@pytest.mark.asyncio
async def test_tool_use_input_is_deanonymized_at_block_stop():
    tool_input = {"command": "nmap -sV SRV-1042"}
    fragments = ['{"command":', ' "nmap -sV SRV-10', '42"}']
    events = [
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "tool_use", "id": "tu_1", "name": "bash", "input": {}}},
        *[
            {"type": "content_block_delta", "index": 0,
             "delta": {"type": "input_json_delta", "partial_json": f}}
            for f in fragments
        ],
        {"type": "content_block_stop", "index": 0},
    ]
    out = await _collect(events, MAPPINGS)
    # Reassemble the tool input JSON the transform emitted.
    emitted = "".join(
        e["delta"]["partial_json"]
        for e in out
        if e.get("type") == "content_block_delta"
        and e["delta"].get("type") == "input_json_delta"
    )
    assert json.loads(emitted) == {"command": "nmap -sV 10.10.14.22"}
    # start and stop for the block are preserved
    assert out[0]["type"] == "content_block_start"
    assert out[-1]["type"] == "content_block_stop"


def test_encode_sse_uses_event_type_and_json_data():
    out = encode_sse("ping", {"type": "ping"})
    assert out == 'event: ping\ndata: {"type": "ping"}\n\n'


async def _byte_iter(chunks):
    for c in chunks:
        yield c.encode("utf-8") if isinstance(c, str) else c


@pytest.mark.asyncio
async def test_iter_sse_events_reassembles_across_chunk_boundaries():
    # A single SSE event whose `data:` JSON is split mid-token across raw chunks.
    raw = 'event: message_start\ndata: {"type": "message_start", "id": "m1"}\n\n'
    chunks = [raw[:20], raw[20:35], raw[35:]]
    got = [e async for e in iter_sse_events(_byte_iter(chunks))]
    assert got == [{"type": "message_start", "id": "m1"}]


@pytest.mark.asyncio
async def test_iter_sse_events_parses_multiple_events_in_one_chunk():
    raw = (
        'event: ping\ndata: {"type": "ping"}\n\n'
        'event: message_stop\ndata: {"type": "message_stop"}\n\n'
    )
    got = [e async for e in iter_sse_events(_byte_iter([raw]))]
    assert got == [{"type": "ping"}, {"type": "message_stop"}]


@pytest.mark.asyncio
async def test_envelope_events_pass_through_unchanged():
    events = [
        {"type": "message_start", "message": {"id": "msg_1"}},
        {"type": "ping"},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 5}},
        {"type": "message_stop"},
    ]
    out = await _collect(events, MAPPINGS)
    assert out == events
