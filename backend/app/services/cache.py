from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")


class TTLCache:
    """An in-process cache whose entries expire after a fixed lifetime.

    Repeat lookups of the same indicator are served locally, which keeps a
    free-tier VirusTotal quota from being spent on refreshes a user did not ask
    for.
    """

    def __init__(self, ttl_seconds: int) -> None:
        """Create a cache whose entries live for `ttl_seconds`."""
        self._ttl = ttl_seconds
        self._entries: dict[str, tuple[float, Any]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._guard = asyncio.Lock()

    def get(self, key: str) -> Any | None:
        """Return the live value stored under `key`, or `None` when absent or expired."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at < time.monotonic():
            self._entries.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Store `value` under `key` for this cache's lifetime."""
        self._entries[key] = (time.monotonic() + self._ttl, value)

    def clear(self) -> None:
        """Discard every stored entry."""
        self._entries.clear()

    async def get_or_fetch(
        self, key: str, fetch: Callable[[], Awaitable[T]]
    ) -> tuple[T, bool]:
        """Return the value for `key`, calling `fetch` only when it is not cached.

        Concurrent callers asking for the same key wait on a single `fetch`, so a
        burst of identical requests costs one upstream call.

        Args:
            key: Cache key identifying the value.
            fetch: Coroutine function producing the value when it is missing.

        Returns:
            A pair of the value and whether it came from the cache.
        """
        cached = self.get(key)
        if cached is not None:
            return cached, True

        async with self._guard:
            lock = self._locks.setdefault(key, asyncio.Lock())

        async with lock:
            cached = self.get(key)
            if cached is not None:
                return cached, True
            value = await fetch()
            self.set(key, value)

        async with self._guard:
            self._locks.pop(key, None)

        return value, False
