"""
Unit tests for OpenAI-compatible streaming de-anonymization.

OpenAI /v1/chat/completions streams differ from Anthropic:
  - text arrives in choices[].delta.content (incremental)
  - tool calls arrive in choices[].delta.tool_calls[].function.arguments
    (incremental JSON fragments), ended by finish_reason, not a block-stop
  - the stream terminates with a literal `data: [DONE]` sentinel

The transform must de-anonymize text boundary-safely, buffer tool-call
arguments and de-anonymize them whole, and preserve [DONE].
"""
import json

import pytest

from src.providers.openai_compat import (
    deanonymize_openai_stream,
    encode_openai_sse,
    iter_openai_sse,
)

MAPPINGS = [("SRV-1042", "10.10.14.22"), ("USR-77", "j.martins")]
DONE = "[DONE]"


async def _aiter(items):
    for it in items:
        yield it


async def _collect(items, mappings):
    return [e async for e in deanonymize_openai_stream(_aiter(items), mappings)]


def _content_of(out):
    parts = []
    for ev in out:
        if ev == DONE:
            continue
        for ch in ev.get("choices", []):
            c = ch.get("delta", {}).get("content")
            if isinstance(c, str):
                parts.append(c)
    return "".join(parts)


def _chunk(delta, finish=None, index=0):
    return {
        "id": "chatcmpl-1", "object": "chat.completion.chunk", "model": "m",
        "choices": [{"index": index, "delta": delta, "finish_reason": finish}],
    }


class TestText:
    @pytest.mark.asyncio
    async def test_content_split_across_chunks_is_deanonymized(self):
        events = [
            _chunk({"role": "assistant"}),
            _chunk({"content": "host SRV-10"}),
            _chunk({"content": "42 is up"}),
            _chunk({}, finish="stop"),
            DONE,
        ]
        out = await _collect(events, MAPPINGS)
        assert _content_of(out) == "host 10.10.14.22 is up"
        assert "SRV-1042" not in _content_of(out)

    @pytest.mark.asyncio
    async def test_done_sentinel_is_preserved(self):
        out = await _collect([_chunk({"content": "hi"}), _chunk({}, finish="stop"), DONE], MAPPINGS)
        assert out[-1] == DONE

    @pytest.mark.asyncio
    async def test_role_is_preserved(self):
        out = await _collect([_chunk({"role": "assistant"}), _chunk({}, finish="stop"), DONE], MAPPINGS)
        roles = [
            ch["delta"].get("role")
            for ev in out if ev != DONE
            for ch in ev.get("choices", [])
        ]
        assert "assistant" in roles


class TestToolCalls:
    @pytest.mark.asyncio
    async def test_tool_call_arguments_are_deanonymized_whole(self):
        events = [
            _chunk({"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                    "function": {"name": "bash", "arguments": ""}}]}),
            _chunk({"tool_calls": [{"index": 0, "function": {"arguments": '{"cmd": "nmap SRV-10'}}]}),
            _chunk({"tool_calls": [{"index": 0, "function": {"arguments": '42"}'}}]}),
            _chunk({}, finish="tool_calls"),
            DONE,
        ]
        out = await _collect(events, MAPPINGS)
        # Reassemble arguments fragments the transform emitted for tool index 0.
        args = "".join(
            tc.get("function", {}).get("arguments", "")
            for ev in out if ev != DONE
            for ch in ev.get("choices", [])
            for tc in ch.get("delta", {}).get("tool_calls", []) or []
            if tc.get("index") == 0
        )
        assert json.loads(args) == {"cmd": "nmap 10.10.14.22"}
        # id/name/type carried through
        emitted = [
            tc
            for ev in out if ev != DONE
            for ch in ev.get("choices", [])
            for tc in ch.get("delta", {}).get("tool_calls", []) or []
        ]
        assert any(tc.get("id") == "call_1" for tc in emitted)
        assert any(tc.get("function", {}).get("name") == "bash" for tc in emitted)
        # finish_reason preserved
        finishes = [ch.get("finish_reason") for ev in out if ev != DONE for ch in ev.get("choices", [])]
        assert "tool_calls" in finishes


class TestCodec:
    def test_encode_done(self):
        assert encode_openai_sse(DONE) == "data: [DONE]\n\n"

    def test_encode_chunk(self):
        assert encode_openai_sse({"a": 1}) == 'data: {"a": 1}\n\n'

    @pytest.mark.asyncio
    async def test_iter_parses_chunks_and_done(self):
        raw = (
            'data: {"id": "c1", "choices": []}\n\n'
            "data: [DONE]\n\n"
        )
        async def _bytes():
            yield raw[:15].encode()
            yield raw[15:].encode()
        got = [e async for e in iter_openai_sse(_bytes())]
        assert got == [{"id": "c1", "choices": []}, "[DONE]"]
