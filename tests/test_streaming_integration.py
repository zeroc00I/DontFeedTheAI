"""
End-to-end test of the /v1/messages streaming path.

Drives the real proxy_messages streaming branch through the ASGI app with a
mocked Anthropic upstream: a surrogate is split across two text deltas in the
upstream SSE, and the client must receive the de-anonymized original with no
surrogate leaking — proving the wiring, not just the transform units.
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


def _sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


@pytest.mark.asyncio
async def test_streaming_response_is_deanonymized_end_to_end(db_path, mock_llm_empty):
    original = "10.10.14.22"
    surrogate, _ = get_or_create(original, "IP_ADDRESS", generate_surrogate, db_path=db_path)
    assert surrogate != original

    half = len(surrogate) // 2
    upstream_chunks = [
        _sse("message_start", {"type": "message_start",
                               "message": {"id": "m1", "type": "message", "role": "assistant",
                                           "content": [], "model": "claude", "usage": {}}}),
        _sse("content_block_start", {"type": "content_block_start", "index": 0,
                                     "content_block": {"type": "text", "text": ""}}),
        _sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                     "delta": {"type": "text_delta", "text": f"host {surrogate[:half]}"}}),
        _sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                     "delta": {"type": "text_delta", "text": f"{surrogate[half:]} is up"}}),
        _sse("content_block_stop", {"type": "content_block_stop", "index": 0}),
        _sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {}}),
        _sse("message_stop", {"type": "message_stop"}),
    ]

    body = {
        "model": "claude-x",
        "stream": True,
        "messages": [{"role": "user", "content": "scan the host please"}],
    }

    received = ""
    # Construct the test client with the REAL httpx.AsyncClient first, then patch
    # only for the request so main's stream-time lookup hits the fake upstream
    # (main.httpx is the same module object as this test's httpx).
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as ac:
        with patch.object(main.httpx, "AsyncClient", _fake_client_factory(upstream_chunks)):
            async with ac.stream("POST", "/v1/messages", json=body) as r:
                assert r.status_code == 200
                assert r.headers["content-type"].startswith("text/event-stream")
                async for chunk in r.aiter_bytes():
                    received += chunk.decode("utf-8")

    # The real IP reached the client...
    assert original in received
    # ...and the surrogate never leaked through.
    assert surrogate not in received
    # ...and it arrived as a proper streamed text_delta, not one buffered blob.
    assert "content_block_delta" in received
    assert "message_stop" in received
