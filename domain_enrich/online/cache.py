"""Async keyed cache with single-flight.

The biggest speed lever for large lists is *not re-fetching* data that many
domains share: an IP's geo/network, an ASN's operator, a TLD's RDAP server.
This cache stores results by key and, crucially, coalesces concurrent misses
for the same key into a single in-flight coroutine (single-flight) so a network
shared by 10k domains is fetched exactly once.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Dict, Hashable, TypeVar

V = TypeVar("V")


class AsyncCache:
    def __init__(self):
        self._values: Dict[Hashable, object] = {}
        self._inflight: Dict[Hashable, asyncio.Future] = {}

    def __contains__(self, key: Hashable) -> bool:
        return key in self._values

    def __len__(self) -> int:
        return len(self._values)

    async def get(self, key: Hashable, factory: Callable[[], Awaitable[V]]) -> V:
        """Return cached ``key`` or compute it via ``factory`` exactly once.

        Concurrent callers that miss on the same key await the same result; a
        failing factory propagates to all waiters and is not cached.
        """
        if key in self._values:
            return self._values[key]  # type: ignore[return-value]

        inflight = self._inflight.get(key)
        if inflight is not None:
            return await inflight

        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._inflight[key] = fut
        try:
            result = await factory()
        except BaseException as exc:  # noqa: BLE001 - propagate to all waiters
            self._inflight.pop(key, None)
            if not fut.done():
                fut.set_exception(exc)
            raise
        else:
            self._values[key] = result
            self._inflight.pop(key, None)
            if not fut.done():
                fut.set_result(result)
            return result
