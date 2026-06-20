"""Tests for n8n HTTP client with retry and backoff."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from tengen.n8n.client import N8nClient, N8nRequestFailed


@pytest.fixture
def client():
    return N8nClient(timeout=5, max_retries=3, backoff_base=0.01)


@pytest.mark.asyncio
async def test_successful_post(client):
    mock_response = httpx.Response(200, json={"result": "ok"})
    with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_response):
        result = await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"result": "ok"}


@pytest.mark.asyncio
async def test_retries_on_500(client):
    fail = httpx.Response(500, text="Internal Server Error")
    success = httpx.Response(200, json={"result": "ok"})
    mock_post = AsyncMock(side_effect=[fail, fail, success])
    with patch.object(client._client, "post", mock_post):
        result = await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"result": "ok"}
    assert mock_post.call_count == 3


@pytest.mark.asyncio
async def test_raises_after_exhausted_retries(client):
    fail = httpx.Response(500, text="Internal Server Error")
    mock_post = AsyncMock(return_value=fail)
    with patch.object(client._client, "post", mock_post):
        with pytest.raises(N8nRequestFailed) as exc_info:
            await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert "500" in str(exc_info.value)
    assert mock_post.call_count == 3


@pytest.mark.asyncio
async def test_no_retry_on_4xx(client):
    fail = httpx.Response(422, json={"error": "bad payload"})
    mock_post = AsyncMock(return_value=fail)
    with patch.object(client._client, "post", mock_post):
        with pytest.raises(N8nRequestFailed) as exc_info:
            await client.execute("https://n8n.example.com/webhook/test", {"bad": True})
    assert "422" in str(exc_info.value)
    assert mock_post.call_count == 1  # No retry


@pytest.mark.asyncio
async def test_retries_on_timeout(client):
    success = httpx.Response(200, json={"ok": True})
    mock_post = AsyncMock(side_effect=[httpx.TimeoutException("timed out"), success])
    with patch.object(client._client, "post", mock_post):
        result = await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"ok": True}
    assert mock_post.call_count == 2


@pytest.mark.asyncio
async def test_retries_on_connect_error(client):
    success = httpx.Response(200, json={"ok": True})
    mock_post = AsyncMock(side_effect=[httpx.ConnectError("refused"), success])
    with patch.object(client._client, "post", mock_post):
        result = await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_execute_sync(client):
    mock_response = httpx.Response(200, json={"sync": True})
    with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_response):
        result = client.execute_sync("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"sync": True}
