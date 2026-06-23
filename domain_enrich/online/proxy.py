"""SOCKS5 proxy provider: fetch public lists, cache to disk, round-robin.

Public free-proxy lists are downloaded (first URL that returns content wins),
parsed into ``host:port`` entries, cached on disk with a TTL, and served in a
shuffled round-robin. The HTTP fetch and the clock are injectable so the whole
module is testable without real network or sleeping.
"""

from __future__ import annotations

import asyncio
import os
import random
import re
import sys
import time
from typing import Awaitable, Callable, List, Optional

DEFAULT_PROXY_URLS = [
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
]
DEFAULT_TTL_SECONDS = 6 * 3600

_HOSTPORT_RE = re.compile(r"^([A-Za-z0-9.\-]+):(\d{1,5})$")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def parse_proxies(text: str) -> List[str]:
    """Parse a proxy list into deduped ``host:port`` strings.

    Handles both bare ``host:port`` (iplocate) and ``socks5://host:port``
    (proxifly) line formats; drops comments and anything malformed.
    """
    out: List[str] = []
    seen = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "://" in s:
            s = s.split("://", 1)[1]
        s = s.split("@")[-1]      # drop any user:pass@
        s = s.split("/")[0]       # drop any trailing path
        m = _HOSTPORT_RE.match(s)
        if not m:
            continue
        if not (0 < int(m.group(2)) < 65536):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


async def _default_fetch(url: str, timeout: float = 20.0) -> Optional[str]:
    import httpx
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(url)
        if resp.status_code >= 400:
            return None
        return resp.text


class ProxyProvider:
    def __init__(self, urls: Optional[List[str]] = None, *,
                 cache_path: Optional[str] = None,
                 ttl_seconds: float = DEFAULT_TTL_SECONDS,
                 local_file: Optional[str] = None,
                 fetcher: Optional[Callable[[str], Awaitable[Optional[str]]]] = None,
                 now: Optional[Callable[[], float]] = None,
                 log: Optional[Callable[[str], None]] = None):
        self.urls = list(urls) if urls else list(DEFAULT_PROXY_URLS)
        self.cache_path = cache_path
        self.ttl_seconds = float(ttl_seconds)
        self.local_file = local_file
        self._fetcher = fetcher or _default_fetch
        self._now = now or time.time
        self._log = log or _log
        self._proxies: List[str] = []
        self._idx = 0
        self._loaded = False
        self._lock = asyncio.Lock()

    async def ensure_loaded(self) -> None:
        async with self._lock:
            if self._loaded:
                return
            proxies = await self._load()
            random.shuffle(proxies)
            self._proxies = proxies
            self._idx = 0
            self._loaded = True
            self._log(f"[proxy] loaded {len(proxies)} socks5 proxies")

    async def acquire(self) -> Optional[str]:
        if not self._loaded:
            await self.ensure_loaded()
        async with self._lock:
            if not self._proxies:
                return None
            proxy = self._proxies[self._idx % len(self._proxies)]
            self._idx += 1
            return f"socks5://{proxy}"

    # -- internals -------------------------------------------------------
    async def _load(self) -> List[str]:
        if self.local_file:
            return self._read_file(self.local_file)
        if self.cache_path and self._cache_fresh():
            cached = self._read_file(self.cache_path)
            if cached:
                return cached
        fetched = await self._fetch_all()
        if fetched:
            self._write_cache(fetched)
            return fetched
        if self.cache_path and os.path.exists(self.cache_path):
            return self._read_file(self.cache_path)
        return []

    def _read_file(self, path: str) -> List[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return parse_proxies(fh.read())
        except OSError as exc:
            self._log(f"[proxy] read {path} failed: {exc}")
            return []

    def _cache_fresh(self) -> bool:
        try:
            mtime = os.path.getmtime(self.cache_path)
        except OSError:
            return False
        return (self._now() - mtime) < self.ttl_seconds

    async def _fetch_all(self) -> List[str]:
        for url in self.urls:
            try:
                text = await self._fetcher(url)
            except Exception as exc:  # noqa: BLE001
                self._log(f"[proxy] fetch {url} failed: {exc}")
                text = None
            if text:
                proxies = parse_proxies(text)
                if proxies:
                    self._log(f"[proxy] fetched {len(proxies)} from {url}")
                    return proxies
        return []

    def _write_cache(self, proxies: List[str]) -> None:
        if not self.cache_path:
            return
        try:
            os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(proxies) + "\n")
        except OSError as exc:
            self._log(f"[proxy] cache write failed: {exc}")
