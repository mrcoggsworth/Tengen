"""Per-principal cache used by enrichers.

PrincipalCache — abstract interface
InProcessTTLCache — in-process TTL+LRU, used per runbook pod

The ABC exists so a Redis-backed implementation can be swapped in later.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Any, Callable


class PrincipalCache(ABC):
    """Abstract cache keyed by (namespace, key) with per-entry TTL."""

    @abstractmethod
    def get(self, key: str, namespace: str) -> Any | None: ...

    @abstractmethod
    def set(self, key: str, namespace: str, value: Any, ttl: int) -> None: ...

    @abstractmethod
    def stats(self) -> dict[str, int]: ...


class InProcessTTLCache(PrincipalCache):
    """In-process TTL+LRU cache backed by OrderedDict.

    - Per-entry TTL via expires_at.
    - LRU eviction when max_size is reached.
    - Clock is injectable for deterministic unit tests.
    """

    def __init__(
        self,
        max_size: int = 5000,
        default_ttl: int = 900,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        if default_ttl <= 0:
            raise ValueError("default_ttl must be positive")
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._clock = clock
        self._store: OrderedDict[tuple[str, str], tuple[Any, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    @property
    def default_ttl(self) -> int:
        return self._default_ttl

    def get(self, key: str, namespace: str) -> Any | None:
        ck = (namespace, key)
        entry = self._store.get(ck)
        if entry is None:
            self._misses += 1
            return None
        value, expires_at = entry
        if self._clock() >= expires_at:
            del self._store[ck]
            self._misses += 1
            return None
        self._store.move_to_end(ck)
        self._hits += 1
        return value

    def set(self, key: str, namespace: str, value: Any, ttl: int) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        ck = (namespace, key)
        expires_at = self._clock() + ttl
        if ck in self._store:
            self._store[ck] = (value, expires_at)
            self._store.move_to_end(ck)
            return
        if len(self._store) >= self._max_size:
            self._store.popitem(last=False)
            self._evictions += 1
        self._store[ck] = (value, expires_at)

    def stats(self) -> dict[str, int]:
        return {
            "hits": self._hits,
            "misses": self._misses,
            "evictions": self._evictions,
            "size": len(self._store),
        }
