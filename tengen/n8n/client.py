"""n8n webhook HTTP client with retry and exponential backoff."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class N8nRequestFailed(Exception):
    """All retries exhausted or non-retryable HTTP error."""

    def __init__(self, url: str, status: int | None, detail: str, attempts: int) -> None:
        self.url = url
        self.status = status
        self.detail = detail
        self.attempts = attempts
        super().__init__(f"n8n request failed: url={url} status={status} attempts={attempts} detail={detail}")


class N8nClient:
    """POST payloads to n8n webhooks with retry logic.

    Retries on 5xx, timeout, and connection errors.
    No retry on 4xx (client error — not transient).
    """

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        backoff_base: float = 2.0,
    ) -> None:
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._client = httpx.AsyncClient(timeout=timeout)

    async def execute(self, webhook_url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST payload to webhook_url and return parsed JSON response.

        Retries up to max_retries on transient failures.
        Raises N8nRequestFailed on exhausted retries or non-retryable errors.
        """
        last_error: str = ""
        last_status: int | None = None

        for attempt in range(self._max_retries):
            try:
                response = await self._client.post(webhook_url, json=payload)

                if response.status_code < 400:
                    return response.json()

                # 4xx — client error, don't retry
                if 400 <= response.status_code < 500:
                    raise N8nRequestFailed(
                        url=webhook_url,
                        status=response.status_code,
                        detail=response.text[:500],
                        attempts=1,
                    )

                # 5xx — server error, retry
                last_status = response.status_code
                last_error = response.text[:500]
                logger.warning(
                    "n8n webhook %s returned %d (attempt %d/%d)",
                    webhook_url, response.status_code, attempt + 1, self._max_retries,
                )

            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_status = None
                last_error = str(exc)
                logger.warning(
                    "n8n webhook %s connection error (attempt %d/%d): %s",
                    webhook_url, attempt + 1, self._max_retries, exc,
                )

            except N8nRequestFailed:
                raise

            # Backoff before next attempt (skip after last attempt)
            if attempt < self._max_retries - 1:
                delay = self._backoff_base ** attempt
                await asyncio.sleep(delay)

        raise N8nRequestFailed(
            url=webhook_url,
            status=last_status,
            detail=last_error,
            attempts=self._max_retries,
        )

    def execute_sync(self, webhook_url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Sync wrapper for use in ADK FunctionTool contexts."""
        return asyncio.run(self.execute(webhook_url, payload))

    async def close(self) -> None:
        await self._client.aclose()
