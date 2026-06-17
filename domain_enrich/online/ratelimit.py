"""Async token-bucket rate limiter.

Each network source that imposes a published limit (ip-api at 45 req/min,
abuse.ch fair-use) gets its own limiter. ``acquire()`` awaits until a token is
available, so up to ``rate`` calls proceed per ``per`` seconds and no more —
parallelism is allowed up to the limit, then callers queue.

A ``rate`` of 0 or less means "no limit": ``acquire()`` returns immediately.
"""

from __future__ import annotations

import asyncio
from typing import Optional


class RateLimiter:
    def __init__(self, rate: float, per: float = 60.0,
                 loop_time: Optional[callable] = None):
        """``rate`` tokens refill over ``per`` seconds (default per minute)."""
        self.rate = float(rate)
        self.per = float(per)
        self._tokens = float(rate)
        self._lock = asyncio.Lock()
        # Injectable clock makes the refill logic unit-testable without sleeping.
        self._now = loop_time or (lambda: asyncio.get_event_loop().time())
        self._updated = self._now()

    @property
    def unlimited(self) -> bool:
        return self.rate <= 0

    def _refill(self) -> None:
        now = self._now()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.rate, self._tokens + elapsed * self.rate / self.per)
            self._updated = now

    async def acquire(self) -> None:
        if self.unlimited:
            return
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                # Time until one more token accrues.
                deficit = 1 - self._tokens
                wait = deficit * self.per / self.rate
            await asyncio.sleep(wait)

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *exc):
        return False
