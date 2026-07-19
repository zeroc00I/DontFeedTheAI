"""
End-to-end test of the /v1/chat/completions streaming path.

Drives the real proxy_chat_completions streaming branch through the ASGI app
with a mocked OpenAI-compatible upstream: a surrogate is split across two
content deltas, and the client must receive the de-anonymized original with no
surrogate leaking, terminated by [DONE].
"""
import json
from unittest.mock import patch

import httpx
import pytest

from src import main
from src.surrogates import generate_surrogate
from src.vault import get_or_create


class _FakeResp:
    def __init__(self, chunks, status=200):
        self.status_code = status
        self._chunks = chunks

    async def aiter_bytes(self):
        for c in self._chunks:
            yield c

    async def aread(self):
        return b"".join(self._chunks)


class _FakeStreamCtx:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *a):
        return False


def _fake_client_factory(chunks):
    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url, **k):
            return _FakeStreamCtx(_FakeResp(chunks))

    return _FakeClient


def _sse(obj):
    if obj == "[DONE]":
        return b"data: [DONE]\n\n"
    return f"data: {json.dumps(obj)}\n\n".encode()


def _chunk(delta, finish=None):
    return {
        "id": "c1", "object": "chat.completion.chunk", "model": "gpt-x",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }


@pytest.mark.asyncio
async def test_openai_streaming_response_is_deanonymized_end_to_end(db_path, mock_llm_empty):
    original = "10.10.14.22"
    surrogate, _ = get_or_create(original, "IP_ADDRESS", generate_surrogate, db_path=db_path)
    half = len(surrogate) // 2
    upstream_chunks = [
        _sse(_chunk({"role": "assistant"})),
        _sse(_chunk({"content": f"host {surrogate[:half]}"})),
        _sse(_chunk({"content": f"{surrogate[half:]} is up"})),
        _sse(_chunk({}, finish="stop")),
        _sse("[DONE]"),
    ]

    body = {
        "model": "gpt-x",
        "stream": True,
        "messages": [{"role": "user", "content": "scan the host please"}],
    }

    received = ""
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as ac:
        with patch.object(main.httpx, "AsyncClient", _fake_client_factory(upstream_chunks)):
            async with ac.stream("POST", "/v1/chat/completions", json=body) as r:
                assert r.status_code == 200
                assert r.headers["content-type"].startswith("text/event-stream")
                async for chunk in r.aiter_bytes():
                    received += chunk.decode("utf-8")

    assert original in received
    assert surrogate not in received
    assert "chat.completion.chunk" in received
    assert "data: [DONE]" in received
