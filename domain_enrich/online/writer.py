"""Batched async SQLite writer.

SQLite is single-writer, so every DB touch in the online run is funneled through
ONE dedicated thread (a single-worker executor that owns the connection). Worker
coroutines never write directly: they ``submit`` operations that are buffered
and applied in batched transactions, keeping the event loop unblocked while
preserving the offline mode's resume guarantees.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List


class AsyncWriter:
    def __init__(self, store_factory: Callable[[], object],
                 batch_size: int = 500):
        self._factory = store_factory
        self._executor = ThreadPoolExecutor(max_workers=1,
                                             thread_name_prefix="de-sqlite")
        self._store = None
        self._buf: List[Callable[[object], None]] = []
        self._buf_lock = asyncio.Lock()
        self._batch_size = batch_size

    async def _run(self, fn: Callable[[], object]):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, fn)

    async def start(self) -> None:
        self._store = await self._run(self._factory)

    async def call(self, fn: Callable[[object], object]):
        """Run ``fn(store)`` in the writer thread and return its result.

        Used for reads (load pending domains), normalize, marks and export —
        anything that must touch the connection.
        """
        return await self._run(lambda: fn(self._store))

    async def submit(self, op: Callable[[object], None]) -> None:
        """Buffer a write op; flush when the batch is full."""
        async with self._buf_lock:
            self._buf.append(op)
            full = len(self._buf) >= self._batch_size
        if full:
            await self.flush()

    async def flush(self) -> None:
        async with self._buf_lock:
            if not self._buf:
                return
            ops = self._buf
            self._buf = []

        def apply(store):
            with store.batch():
                for op in ops:
                    op(store)

        await self._run(lambda: apply(self._store))

    async def close(self) -> None:
        await self.flush()
        if self._store is not None:
            await self._run(lambda: self._store.close())
        self._executor.shutdown(wait=True)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc):
        await self.close()
        return False
