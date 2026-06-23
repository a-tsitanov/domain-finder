# Proxy-aware rendering + availability checker — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SOCKS5 proxy fallback to Playwright page rendering and a standalone resource-availability checker that uses the same proxy pool.

**Architecture:** A new `ProxyProvider` (fetch public SOCKS5 lists → parse → disk-cache → round-robin) is shared by two consumers: `render_page` retries failed renders through proxy-bound browser contexts (≤25 attempts), and a new `checker` module probes resources over httpx, falling back to the same proxies on connection failure. Both log every proxy use. CLI exposes a new `check` command and proxy options on `run-online`.

**Tech Stack:** Python 3.10+, asyncio, click, httpx (`httpx[socks]` for SOCKS5), Playwright (Chromium), pytest + pytest-asyncio.

## Global Constraints

- Python `>=3.10`; follow existing module style (module docstring, `from __future__ import annotations`, stderr `_log` helpers).
- Tests must NOT touch the real network or launch a real browser — use httpx `MockTransport`, fakes, and injected fetch/clock functions, matching `tests/test_online.py`.
- SOCKS5 only. Proxy string form is `socks5://host:port`.
- `max_proxy_attempts` default is **25** everywhere.
- Default proxy URLs (verbatim): `https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt` then `https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt`.
- Cache TTL default `6*3600` seconds; default cache path `work/proxies-socks5.txt` (env `DE_PROXY_CACHE`).
- No new persisted SQLite/parquet columns. Proxy info reaches output only via stderr logs and the JSON dossier field `page_proxy`.
- **COMMIT GATE (user's global rule):** Do NOT run `git commit` without the user's explicit go-ahead. The `Commit` steps below are real steps, but the executor must pause and ask before running them.

---

### Task 1: `ProxyProvider` — fetch, parse, cache, rotate

**Files:**
- Create: `domain_enrich/online/proxy.py`
- Test: `tests/test_proxy.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `parse_proxies(text: str) -> list[str]` — returns `host:port` strings.
  - `DEFAULT_PROXY_URLS: list[str]`, `DEFAULT_TTL_SECONDS: int`.
  - `class ProxyProvider(urls=None, *, cache_path=None, ttl_seconds=DEFAULT_TTL_SECONDS, local_file=None, fetcher=None, now=None, log=None)` with:
    - `async ensure_loaded() -> None`
    - `async acquire() -> str | None` (returns `socks5://host:port`)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_proxy.py
"""Tests for the SOCKS5 ProxyProvider (no real network)."""
from __future__ import annotations

import asyncio

from domain_enrich.online.proxy import ProxyProvider, parse_proxies


def test_parse_strips_scheme_and_rejects_junk():
    text = "\n".join([
        "1.2.3.4:1080",
        "socks5://5.6.7.8:1081",
        "# comment",
        "not-a-proxy",
        "9.9.9.9:99999",      # bad port
        "1.2.3.4:1080",        # dup
        "",
    ])
    assert parse_proxies(text) == ["1.2.3.4:1080", "5.6.7.8:1081"]


async def test_acquire_rotates_round_robin_with_prefix():
    p = ProxyProvider(local_file=None, fetcher=_fixed_fetcher("1.1.1.1:1\n2.2.2.2:2\n3.3.3.3:3"))
    first_cycle = [await p.acquire() for _ in range(3)]
    assert sorted(first_cycle) == ["socks5://1.1.1.1:1", "socks5://2.2.2.2:2", "socks5://3.3.3.3:3"]
    # wraps back to the first proxy of the (shuffled) cycle
    assert await p.acquire() == first_cycle[0]


async def test_acquire_empty_pool_returns_none():
    p = ProxyProvider(fetcher=_fixed_fetcher(""))
    assert await p.acquire() is None


async def test_fresh_disk_cache_is_used_without_fetching(tmp_path):
    cache = tmp_path / "proxies.txt"
    cache.write_text("7.7.7.7:7\n")
    calls = {"n": 0}

    async def fetcher(url):
        calls["n"] += 1
        return "8.8.8.8:8"

    clock = {"t": 1000.0}
    p = ProxyProvider(cache_path=str(cache), ttl_seconds=100,
                      fetcher=fetcher, now=lambda: clock["t"])
    # cache mtime is "now"; advance only 10s -> still fresh
    import os
    os.utime(str(cache), (clock["t"], clock["t"]))
    clock["t"] += 10
    assert await p.acquire() == "socks5://7.7.7.7:7"
    assert calls["n"] == 0


async def test_stale_cache_triggers_fetch_and_rewrite(tmp_path):
    cache = tmp_path / "proxies.txt"
    cache.write_text("7.7.7.7:7\n")
    clock = {"t": 10_000.0}
    import os
    os.utime(str(cache), (0, 0))  # ancient -> stale
    p = ProxyProvider(cache_path=str(cache), ttl_seconds=100,
                      fetcher=_fixed_fetcher("8.8.8.8:8"), now=lambda: clock["t"])
    assert await p.acquire() == "socks5://8.8.8.8:8"
    assert "8.8.8.8:8" in cache.read_text()


async def test_fetch_failure_falls_back_to_stale_cache(tmp_path):
    cache = tmp_path / "proxies.txt"
    cache.write_text("7.7.7.7:7\n")
    import os
    os.utime(str(cache), (0, 0))

    async def bad_fetcher(url):
        raise RuntimeError("network down")

    p = ProxyProvider(cache_path=str(cache), ttl_seconds=100,
                      fetcher=bad_fetcher, now=lambda: 10_000.0)
    assert await p.acquire() == "socks5://7.7.7.7:7"


async def test_url_fallback_order():
    seen = []

    async def fetcher(url):
        seen.append(url)
        return "1.1.1.1:1" if "proxifly" in url else None

    p = ProxyProvider(urls=["http://first/iplocate", "http://second/proxifly"],
                      fetcher=fetcher)
    assert await p.acquire() == "socks5://1.1.1.1:1"
    assert seen == ["http://first/iplocate", "http://second/proxifly"]


def _fixed_fetcher(text):
    async def fetcher(url):
        return text
    return fetcher
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_proxy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'domain_enrich.online.proxy'`

- [ ] **Step 3: Write `domain_enrich/online/proxy.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_proxy.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit** *(pause for user go-ahead per COMMIT GATE)*

```bash
git add domain_enrich/online/proxy.py tests/test_proxy.py
git commit -m "feat(online): add SOCKS5 ProxyProvider (fetch/cache/rotate)"
```

---

### Task 2: Proxy fallback in `render_page`

**Files:**
- Modify: `domain_enrich/online/render.py` (rewrite)
- Test: `tests/test_online.py` (extend — add fakes + tests)

**Interfaces:**
- Consumes: `ProxyProvider.acquire()` from Task 1 (any object with `async acquire() -> str | None`).
- Produces: `async render_page(browser, domain, *, timeout_ms=20000, wait_until="load", proxy_provider=None, max_proxy_attempts=25, log=None) -> dict` — same dict keys as before plus `page_proxy: str | None`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_online.py`)

Add these fakes near the existing `FakeBrowser` (after it):

```python
class FakeContext:
    def __init__(self, html, fail=False):
        self._html, self._fail = html, fail

    async def new_page(self):
        if self._fail:
            raise RuntimeError("proxy refused")
        return FakePage(self._html)

    async def close(self):
        pass


class ProxyFallbackBrowser:
    """Direct new_page() always fails; proxied contexts succeed."""
    def __init__(self, html="<p>via proxy</p>", fail_contexts=0):
        self.html = html
        self.fail_contexts = fail_contexts   # first N contexts also fail
        self.contexts = 0

    async def new_page(self):
        raise RuntimeError("direct blocked")

    async def new_context(self, proxy=None):
        self.contexts += 1
        fail = self.contexts <= self.fail_contexts
        return FakeContext(self.html, fail=fail)


class StubProvider:
    def __init__(self, n=30):
        self._proxies = [f"socks5://10.0.0.{i}:1080" for i in range(1, n + 1)]
        self.handed = 0

    async def ensure_loaded(self):
        pass

    async def acquire(self):
        if self.handed >= len(self._proxies):
            return None
        p = self._proxies[self.handed]
        self.handed += 1
        return p
```

Add these tests at the end of the file:

```python
async def test_render_no_provider_unchanged_and_sets_page_proxy_none():
    out = await render_mod.render_page(FakeBrowser("<h1>hi</h1>"), "example.com")
    assert out["page_html"] == "<h1>hi</h1>"
    assert out["page_proxy"] is None


async def test_render_falls_back_to_proxy_on_direct_failure():
    logs = []
    prov = StubProvider()
    out = await render_mod.render_page(
        ProxyFallbackBrowser("<p>ok</p>"), "blocked.com",
        proxy_provider=prov, log=logs.append)
    assert out["page_html"] == "<p>ok</p>"
    assert out["page_proxy"] == "socks5://10.0.0.1:1080"
    assert any("attempt 1/25" in m and "ok" in m for m in logs)


async def test_render_proxy_attempts_capped_at_max():
    logs = []
    prov = StubProvider()
    # every context fails -> exhaust attempts, never succeed
    out = await render_mod.render_page(
        ProxyFallbackBrowser(fail_contexts=999), "blocked.com",
        proxy_provider=prov, max_proxy_attempts=25, log=logs.append)
    assert out["page_html"] is None
    assert out["page_proxy"] is None
    assert prov.handed == 25
    assert sum(1 for m in logs if "via socks5" in m) == 25


async def test_render_stops_when_proxy_pool_exhausted():
    logs = []
    prov = StubProvider(n=3)
    out = await render_mod.render_page(
        ProxyFallbackBrowser(fail_contexts=999), "blocked.com",
        proxy_provider=prov, max_proxy_attempts=25, log=logs.append)
    assert out["page_html"] is None
    assert prov.handed == 3   # ran out before hitting 25
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_online.py -k render -v`
Expected: FAIL — `render_page() got an unexpected keyword argument 'proxy_provider'` (and `page_proxy` KeyError).

- [ ] **Step 3: Rewrite `domain_enrich/online/render.py`**

```python
"""Rendered-page download via Playwright (async), with SOCKS5 proxy fallback.

Navigates a headless Chromium page to the domain, waits for the DOM to settle,
and captures the full rendered HTML plus metadata (final URL, HTTP status, byte
size). The first attempt is direct (default context, no proxy); if both schemes
fail and a ``proxy_provider`` is supplied, the render is retried through
proxy-bound browser contexts, up to ``max_proxy_attempts`` times, logging each
proxy use. No analysis — HTML is returned verbatim. Never raises.

``render_page`` operates on a minimal browser surface (``new_page``/
``new_context`` → ``goto``/``content``/``close``) so tests can pass a fake
browser without a real Chromium.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


async def _attempt(new_page, domain: str, timeout_ms: int,
                   wait_until: str) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    """Try https then http using ``new_page``; return (page_data, error)."""
    last_error: Optional[str] = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        page = None
        try:
            page = await new_page()
            response = await page.goto(url, timeout=timeout_ms, wait_until=wait_until)
            html = await page.content()
            status = response.status if response is not None else None
            return {
                "page_html": html,
                "page_http_status": status,
                "page_final_url": page.url,
                "page_bytes": len(html.encode("utf-8")) if html else 0,
                "page_fetched_at": _now_iso(),
                "page_error": None,
            }, None
        except Exception as exc:  # noqa: BLE001 - record and try next scheme
            last_error = f"{type(exc).__name__}: {exc}"
        finally:
            if page is not None:
                try:
                    await page.close()
                except Exception:
                    pass
    return None, last_error


async def render_page(browser, domain: str, *, timeout_ms: int = 20000,
                      wait_until: str = "load", proxy_provider=None,
                      max_proxy_attempts: int = 25, log=None) -> Dict[str, object]:
    """Render ``https://<domain>`` (fallback ``http://``) and return page data.

    Tries direct first; on failure, retries through SOCKS5 proxies from
    ``proxy_provider`` (≤ ``max_proxy_attempts``). Returns the page dict plus
    ``page_proxy`` (the proxy that worked, or ``None``).
    """
    log = log or _log

    data, last_error = await _attempt(browser.new_page, domain, timeout_ms, wait_until)
    if data is not None:
        data["page_proxy"] = None
        return data

    if proxy_provider is not None:
        for attempt in range(1, max_proxy_attempts + 1):
            proxy = await proxy_provider.acquire()
            if not proxy:
                break
            context = None
            try:
                context = await browser.new_context(proxy={"server": proxy})
                data, err = await _attempt(context.new_page, domain, timeout_ms, wait_until)
            except Exception as exc:  # noqa: BLE001 - context creation failed
                data, err = None, f"{type(exc).__name__}: {exc}"
            finally:
                if context is not None:
                    try:
                        await context.close()
                    except Exception:
                        pass
            if data is not None:
                log(f"[proxy] {domain} attempt {attempt}/{max_proxy_attempts} via {proxy}: ok")
                data["page_proxy"] = proxy
                return data
            log(f"[proxy] {domain} attempt {attempt}/{max_proxy_attempts} via {proxy}: {err}")
            last_error = err

    return {
        "page_html": None,
        "page_http_status": None,
        "page_final_url": None,
        "page_bytes": 0,
        "page_fetched_at": _now_iso(),
        "page_error": last_error or "render failed",
        "page_proxy": None,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_online.py -k render -v`
Expected: PASS (existing 2 render tests + 4 new)

- [ ] **Step 5: Commit** *(pause for user go-ahead per COMMIT GATE)*

```bash
git add domain_enrich/online/render.py tests/test_online.py
git commit -m "feat(online): SOCKS5 proxy fallback in render_page"
```

---

### Task 3: Availability checker + `httpx[socks]` dependency

**Files:**
- Create: `domain_enrich/online/checker.py`
- Modify: `pyproject.toml:26` (online extras), `requirements.txt:9-11` (comment)
- Test: `tests/test_checker.py`

**Interfaces:**
- Consumes: `ProxyProvider` (Task 1); `USER_AGENT` from `domain_enrich/online/http.py`.
- Produces:
  - `async check_resource(client_factory, resource, *, proxy_provider=None, max_proxy_attempts=25, timeout=15.0, log=None) -> dict` with keys `resource, ok, status, final_url, via_proxy, attempts, error`.
  - `async run_check(input_path, success_path, failed_path, *, concurrency=100, proxy_provider=None, max_proxy_attempts=25, timeout=15.0, client_factory=None, log=None) -> dict` returning `{"checked", "ok", "failed"}`.
  - `run_check_sync(*args, **kwargs) -> dict`.
  - `make_check_client(proxy=None, *, timeout=15.0)` — default httpx client factory.
- `client_factory` is `Callable[[Optional[str]], httpx.AsyncClient]` (called as an async context manager).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_checker.py
"""Tests for the availability checker (httpx MockTransport, no real network)."""
from __future__ import annotations

import httpx

from domain_enrich.online.checker import check_resource, run_check


class StubProvider:
    def __init__(self, n=30):
        self._proxies = [f"socks5://10.0.0.{i}:1080" for i in range(1, n + 1)]
        self.handed = 0

    async def ensure_loaded(self):
        pass

    async def acquire(self):
        if self.handed >= len(self._proxies):
            return None
        p = self._proxies[self.handed]
        self.handed += 1
        return p


def _factory(handler_for):
    """Return a client_factory(proxy)->AsyncClient using a per-proxy handler."""
    def factory(proxy):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler_for(proxy)),
                                 follow_redirects=True)
    return factory


async def test_direct_success_no_proxy():
    def handler_for(proxy):
        return lambda req: httpx.Response(200, request=req)
    res = await check_resource(_factory(handler_for), "example.com")
    assert res["ok"] is True
    assert res["status"] == 200
    assert res["via_proxy"] is None
    assert res["attempts"] == 0


async def test_head_405_falls_back_to_get():
    def handler_for(proxy):
        def h(req):
            if req.method == "HEAD":
                return httpx.Response(405, request=req)
            return httpx.Response(200, request=req)
        return h
    res = await check_resource(_factory(handler_for), "example.com")
    assert res["ok"] is True
    assert res["status"] == 200


async def test_direct_fails_then_proxy_succeeds():
    def handler_for(proxy):
        if proxy is None:
            def boom(req):
                raise httpx.ConnectError("refused", request=req)
            return boom
        return lambda req: httpx.Response(200, request=req)
    prov = StubProvider()
    res = await check_resource(_factory(handler_for), "blocked.com", proxy_provider=prov)
    assert res["ok"] is True
    assert res["via_proxy"] == "socks5://10.0.0.1:1080"
    assert res["attempts"] == 1


async def test_total_failure_caps_attempts():
    def handler_for(proxy):
        def boom(req):
            raise httpx.ConnectError("refused", request=req)
        return boom
    prov = StubProvider()
    res = await check_resource(_factory(handler_for), "dead.com",
                               proxy_provider=prov, max_proxy_attempts=25)
    assert res["ok"] is False
    assert res["attempts"] == 25
    assert res["error"]


async def test_run_check_writes_two_tsv_files(tmp_path):
    inp = tmp_path / "list.txt"
    inp.write_text("good.com\nbad.com\n")
    ok_path = tmp_path / "ok.tsv"
    bad_path = tmp_path / "bad.tsv"

    def handler_for(proxy):
        def h(req):
            if "good.com" in str(req.url):
                return httpx.Response(200, request=req)
            raise httpx.ConnectError("refused", request=req)
        return h

    summary = await run_check(str(inp), str(ok_path), str(bad_path),
                              concurrency=4, proxy_provider=None,
                              client_factory=_factory(handler_for))
    assert summary == {"checked": 2, "ok": 1, "failed": 1}
    ok_lines = ok_path.read_text().splitlines()
    bad_lines = bad_path.read_text().splitlines()
    assert ok_lines[0] == "resource\tstatus\tfinal_url\tvia_proxy"
    assert ok_lines[1].startswith("good.com\t200\t")
    assert bad_lines[0] == "resource\tattempts\terror"
    assert bad_lines[1].startswith("bad.com\t")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_checker.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'domain_enrich.online.checker'`

- [ ] **Step 3: Write `domain_enrich/online/checker.py`**

```python
"""Resource availability checker with SOCKS5 proxy fallback.

Reads a list of resources (domains/URLs/IPs, verbatim), probes each over HTTP:
a direct request first, then — on a connection-level failure — retries through
the shared SOCKS5 proxy pool (≤ ``max_proxy_attempts``), logging every proxy
use. "Available" means an HTTP response was received (the connection worked),
regardless of status code. Writes two TSV files: successes and failures.

Everything network-touching is injectable (``client_factory``) so the module is
testable with httpx ``MockTransport`` and no real network.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Callable, Optional

from .http import USER_AGENT


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def make_check_client(proxy: Optional[str] = None, *, timeout: float = 15.0):
    import httpx
    kwargs = {"timeout": timeout, "follow_redirects": True,
              "headers": {"User-Agent": USER_AGENT}}
    if proxy:
        kwargs["proxy"] = proxy
    return httpx.AsyncClient(**kwargs)


def _candidate_urls(resource: str):
    r = resource.strip()
    if "://" in r:
        return [r]
    return [f"https://{r}", f"http://{r}"]


async def _probe(client, resource: str, timeout: float):
    """Try candidate URLs; return (status, final_url, error).

    status is not None when any HTTP response arrives (HEAD, or GET when the
    server rejects HEAD with 405/501). error is set only on connection failure.
    """
    last_error: Optional[str] = None
    for url in _candidate_urls(resource):
        try:
            resp = await client.head(url, timeout=timeout)
            if resp.status_code in (405, 501):
                resp = await client.get(url, timeout=timeout)
            return resp.status_code, str(resp.url), None
        except Exception as exc:  # noqa: BLE001 - connection-level failure
            last_error = f"{type(exc).__name__}: {exc}"
    return None, None, last_error


async def check_resource(client_factory, resource: str, *, proxy_provider=None,
                         max_proxy_attempts: int = 25, timeout: float = 15.0,
                         log=None) -> dict:
    log = log or _log

    async with client_factory(None) as client:
        status, final_url, err = await _probe(client, resource, timeout)
    if status is not None:
        return {"resource": resource, "ok": True, "status": status,
                "final_url": final_url, "via_proxy": None, "attempts": 0,
                "error": None}

    attempts = 0
    if proxy_provider is not None:
        for attempt in range(1, max_proxy_attempts + 1):
            proxy = await proxy_provider.acquire()
            if not proxy:
                break
            attempts = attempt
            async with client_factory(proxy) as client:
                status, final_url, perr = await _probe(client, resource, timeout)
            if status is not None:
                log(f"[proxy] {resource} attempt {attempt}/{max_proxy_attempts} via {proxy}: ok")
                return {"resource": resource, "ok": True, "status": status,
                        "final_url": final_url, "via_proxy": proxy,
                        "attempts": attempt, "error": None}
            log(f"[proxy] {resource} attempt {attempt}/{max_proxy_attempts} via {proxy}: {perr}")
            err = perr or err

    return {"resource": resource, "ok": False, "status": None,
            "final_url": None, "via_proxy": None, "attempts": attempts,
            "error": err or "unreachable"}


def _write_success(path: str, rows) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("resource\tstatus\tfinal_url\tvia_proxy\n")
        for r in rows:
            fh.write(f"{r['resource']}\t{r['status']}\t"
                     f"{r['final_url'] or ''}\t{r['via_proxy'] or ''}\n")


def _write_failed(path: str, rows) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("resource\tattempts\terror\n")
        for r in rows:
            fh.write(f"{r['resource']}\t{r['attempts']}\t{r['error'] or ''}\n")


async def run_check(input_path: str, success_path: str, failed_path: str, *,
                    concurrency: int = 100, proxy_provider=None,
                    max_proxy_attempts: int = 25, timeout: float = 15.0,
                    client_factory=None, log=None) -> dict:
    log = log or _log
    if client_factory is None:
        client_factory = lambda proxy: make_check_client(proxy, timeout=timeout)
    if proxy_provider is not None:
        await proxy_provider.ensure_loaded()

    resources = []
    with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if s:
                resources.append(s)

    results = []
    queue: asyncio.Queue = asyncio.Queue()
    for r in resources:
        queue.put_nowait(r)

    async def worker():
        while True:
            try:
                resource = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                res = await check_resource(
                    client_factory, resource, proxy_provider=proxy_provider,
                    max_proxy_attempts=max_proxy_attempts, timeout=timeout, log=log)
            except Exception as exc:  # noqa: BLE001 - never let one stall the run
                res = {"resource": resource, "ok": False, "status": None,
                       "final_url": None, "via_proxy": None, "attempts": 0,
                       "error": f"{type(exc).__name__}: {exc}"}
            results.append(res)

    n_workers = min(concurrency, max(1, len(resources)))
    await asyncio.gather(*[worker() for _ in range(n_workers)])

    ok = [r for r in results if r["ok"]]
    bad = [r for r in results if not r["ok"]]
    _write_success(success_path, ok)
    _write_failed(failed_path, bad)
    log(f"[check] {len(results)} checked: {len(ok)} ok, {len(bad)} failed")
    return {"checked": len(results), "ok": len(ok), "failed": len(bad)}


def run_check_sync(*args, **kwargs) -> dict:
    return asyncio.run(run_check(*args, **kwargs))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_checker.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Add the SOCKS5 dependency**

In `pyproject.toml`, change the `online` extras line (currently line 26):

```toml
online = ["httpx[socks]>=0.27", "playwright>=1.44"]
```

In `requirements.txt`, update the online-extras comment block (lines 9-11) to:

```
# Online mode extras (pip install -e '.[online]'):
# httpx[socks]>=0.27  # async HTTP + SOCKS5 proxy (RDAP / ip-api / abuse.ch / Cloudflare / proxy fallback)
# playwright>=1.44    # headless-browser page rendering (+ playwright install chromium)
```

- [ ] **Step 6: Commit** *(pause for user go-ahead per COMMIT GATE)*

```bash
git add domain_enrich/online/checker.py tests/test_checker.py pyproject.toml requirements.txt
git commit -m "feat(online): resource availability checker with proxy fallback"
```

---

### Task 4: Wire the provider into `runner.py`

**Files:**
- Modify: `domain_enrich/online/runner.py` (`_process_domain`, `run_online`, `lookup_online`)
- Test: `tests/test_online.py` (extend e2e)

**Interfaces:**
- Consumes: `ProxyProvider` (Task 1), `render_page(..., proxy_provider=, max_proxy_attempts=)` (Task 2).
- Produces: `run_online(..., proxy_provider=None, max_proxy_attempts=25)` and `lookup_online(..., proxy_provider=None, max_proxy_attempts=25)` accept an injectable provider; `_process_domain(..., proxy_provider=None, max_proxy_attempts=25)`; each dossier record gains `page_proxy`.

- [ ] **Step 1: Write the failing test** (append to `tests/test_online.py`)

```python
async def test_run_online_uses_proxy_when_direct_render_fails(tmp_path):
    inp = tmp_path / "domains.txt"
    inp.write_text("example.com\n")
    db = str(tmp_path / "work.db")
    dossiers = str(tmp_path / "dossiers")

    prov = StubProvider()
    async with mock_client(_e2e_handler) as client:
        await run_online(
            str(inp), db, dossiers, None, do_render=True,
            client=client, resolver=_resolver(),
            browser=ProxyFallbackBrowser("<p>proxied</p>"),
            proxy_provider=prov)
    d = dossier.read_dossier(os.path.join(dossiers, "example.com.dossier.gz"))
    assert d["page_html"] == "<p>proxied</p>"
    assert d["page_proxy"] == "socks5://10.0.0.1:1080"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_online.py::test_run_online_uses_proxy_when_direct_render_fails -v`
Expected: FAIL — `run_online() got an unexpected keyword argument 'proxy_provider'`.

- [ ] **Step 3: Edit `_process_domain`**

Change its signature (currently `domain_enrich/online/runner.py:75-78`) to add the two params before `dossier_dir`:

```python
async def _process_domain(domain, original, *, client, resolver, browser,
                          city_reader, asn_reader, geo_cache, net_cache,
                          ip_matcher, abuse_key, cf_token, do_render,
                          dossier_dir, limiters, render_sem,
                          proxy_provider=None, max_proxy_attempts=25) -> dict:
```

Change the render call (currently `domain_enrich/online/runner.py:111-112`):

```python
        async with render_sem:
            page = await render_mod.render_page(
                browser, domain, proxy_provider=proxy_provider,
                max_proxy_attempts=max_proxy_attempts)
```

After `record["page_html"] = page_html` (currently line 122), add:

```python
    record["page_proxy"] = page.get("page_proxy") if page else None
```

- [ ] **Step 4: Edit `run_online` signature and body**

Add params to the `run_online` signature (after `browser=None,` at `domain_enrich/online/runner.py:168`):

```python
    client=None, resolver=None, browser=None,
    proxy_provider=None, max_proxy_attempts: int = 25,
    write_batch: int = 500,
```

Replace the Playwright launch block (currently `domain_enrich/online/runner.py:245-253`) with:

```python
    if do_render and browser is None:
        try:
            from playwright.async_api import async_playwright
            pw = await async_playwright().start()
            launch_kwargs = {"headless": True}
            if proxy_provider is not None:
                await proxy_provider.ensure_loaded()
                launch_kwargs["proxy"] = {"server": "per-context"}
            browser = await pw.chromium.launch(**launch_kwargs)
            own_browser = True
        except Exception as exc:  # noqa: BLE001
            _log(f"[online] Playwright unavailable ({exc}); rendering disabled")
            do_render = False
```

In the `worker()` body, update the `_process_domain(...)` call (currently `domain_enrich/online/runner.py:269-276`) to pass the two args:

```python
                res = await _process_domain(
                    domain, original, client=client, resolver=resolver,
                    browser=browser, city_reader=city_reader,
                    asn_reader=asn_reader, geo_cache=geo_cache,
                    net_cache=net_cache, ip_matcher=ip_matcher,
                    abuse_key=abuse_key, cf_token=cf_token, do_render=do_render,
                    dossier_dir=dossier_dir, limiters=limiters,
                    render_sem=render_sem, proxy_provider=proxy_provider,
                    max_proxy_attempts=max_proxy_attempts)
```

- [ ] **Step 5: Edit `lookup_online`**

Add params to the signature (currently `domain_enrich/online/runner.py:339-341`):

```python
async def lookup_online(domain: str, *, maxmind_city=None, maxmind_asn=None,
                        abuse_key=None, cf_token=None, do_render=False,
                        proxy_provider=None, max_proxy_attempts=25,
                        client=None, resolver=None, browser=None) -> dict:
```

Update its `_process_domain(...)` call (currently `domain_enrich/online/runner.py:364-370`) to pass them:

```python
        res = await _process_domain(
            norm, domain, client=client, resolver=resolver, browser=browser,
            city_reader=city_reader, asn_reader=asn_reader,
            geo_cache=AsyncCache(), net_cache=AsyncCache(), ip_matcher=None,
            abuse_key=abuse_key, cf_token=cf_token, do_render=do_render,
            dossier_dir=None, limiters=limiters,
            render_sem=asyncio.Semaphore(1), proxy_provider=proxy_provider,
            max_proxy_attempts=max_proxy_attempts)
```

- [ ] **Step 6: Run the full online suite to verify pass + no regressions**

Run: `python -m pytest tests/test_online.py -v`
Expected: PASS (all existing tests + the new proxy e2e test). The existing `test_run_online_e2e` still passes because `FakeBrowser.new_page` succeeds directly and `page_proxy` is `None`.

- [ ] **Step 7: Commit** *(pause for user go-ahead per COMMIT GATE)*

```bash
git add domain_enrich/online/runner.py tests/test_online.py
git commit -m "feat(online): thread ProxyProvider through run_online/lookup_online"
```

---

### Task 5: CLI — `check` command + proxy options on `run-online`

**Files:**
- Modify: `domain_enrich/cli.py` (new `check` command, proxy helper + options on `run-online`)
- Modify: `README.md` (document the new command/options)
- Test: `tests/test_cli_lookup.py` (add a CLI smoke test for `check`)

**Interfaces:**
- Consumes: `ProxyProvider` (Task 1), `run_check_sync` (Task 3), `run_online_sync` (Task 4).
- Produces: `domain-enrich check` command; `--no-proxy/--proxy-file/--proxy-list-url/--proxy-cache/--max-proxy-attempts` options on `run-online`; internal helper `_build_proxy_provider(...)`.

- [ ] **Step 1: Write the failing test** (append to `tests/test_cli_lookup.py`)

The existing file already has `from click.testing import CliRunner` and `from domain_enrich.cli import cli` at the top. The CLI imports `run_check_sync` lazily inside the command (`from .online.checker import run_check_sync`), so we monkeypatch the checker module attribute to avoid any real network. Add:

```python
def test_check_command_is_wired(tmp_path, monkeypatch):
    import domain_enrich.online.checker as checker_mod

    inp = tmp_path / "list.txt"
    inp.write_text("example.com\nbad.com\n")
    ok = tmp_path / "ok.tsv"
    bad = tmp_path / "bad.tsv"

    captured = {}

    def fake_run_check_sync(input_path, success_path, failed_path, **kwargs):
        captured.update(kwargs)
        captured["input_path"] = input_path
        # write minimal valid files so the command can echo a summary
        with open(success_path, "w") as fh:
            fh.write("resource\tstatus\tfinal_url\tvia_proxy\n")
        with open(failed_path, "w") as fh:
            fh.write("resource\tattempts\terror\n")
        return {"checked": 2, "ok": 0, "failed": 2}

    monkeypatch.setattr(checker_mod, "run_check_sync", fake_run_check_sync)

    result = CliRunner().invoke(cli, [
        "check", "--input", str(inp), "--success", str(ok),
        "--failed", str(bad), "--no-proxy", "--max-proxy-attempts", "10",
    ])
    assert result.exit_code == 0, result.output
    assert "checked 2" in result.output
    assert captured["max_proxy_attempts"] == 10
    assert captured["proxy_provider"] is None      # --no-proxy honored
    assert ok.read_text().splitlines()[0] == "resource\tstatus\tfinal_url\tvia_proxy"
    assert bad.read_text().splitlines()[0] == "resource\tattempts\terror"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_lookup.py::test_check_command_is_wired -v`
Expected: FAIL — `Error: No such command 'check'.` (exit_code != 0)

- [ ] **Step 3: Add the proxy helper to `cli.py`**

Add `import os` at the top if not present (check existing imports first). Add this helper after `_split_fields` (near `domain_enrich/cli.py:22`):

```python
def _build_proxy_provider(no_proxy, proxy_file, proxy_list_url, proxy_cache):
    """Construct a ProxyProvider from shared CLI proxy options (or None)."""
    if no_proxy:
        return None
    from .online.proxy import ProxyProvider
    urls = list(proxy_list_url) if proxy_list_url else None
    return ProxyProvider(urls=urls, cache_path=proxy_cache, local_file=proxy_file)
```

- [ ] **Step 4: Add proxy options to `run-online` and pass the provider**

Add these options to `run_online_cmd` (after the existing `--cf-token` option at `domain_enrich/cli.py:385-386`, before `--force`):

```python
@click.option("--no-proxy", is_flag=True, default=False,
              help="Disable SOCKS5 proxy fallback when a render fails.")
@click.option("--proxy-list-url", multiple=True,
              help="SOCKS5 proxy-list URL (repeatable). Default: iplocate+proxifly.")
@click.option("--proxy-file", type=click.Path(),
              help="Use a local SOCKS5 proxy file instead of downloading.")
@click.option("--proxy-cache", envvar="DE_PROXY_CACHE",
              default="work/proxies-socks5.txt", show_default=True, type=click.Path(),
              help="Where to cache the fetched proxy list. Env: DE_PROXY_CACHE")
@click.option("--max-proxy-attempts", default=25, show_default=True,
              help="Max proxy retries per page before giving up.")
```

Update the `run_online_cmd` parameter list to include the new names and build/pass the provider. Replace the function definition + body (currently `domain_enrich/cli.py:389-407`) with:

```python
def run_online_cmd(input_path, db, dossier_dir, output, fmt, fields, concurrency,
                   render_concurrency, no_render, maxmind_city, maxmind_asn,
                   ipthreat, abuse_key, cf_token, no_proxy, proxy_list_url,
                   proxy_file, proxy_cache, max_proxy_attempts, force):
    """Online (live) enrichment: live DNS/RDAP/TLS/geo/threat + Playwright page.

    Writes one <domain>.dossier.gz per domain (report + rendered HTML) and an
    optional aggregate table. Fully async and resumable. When a render fails,
    it retries through SOCKS5 proxies (disable with --no-proxy).
    """
    from .online.runner import run_online_sync
    proxy_provider = _build_proxy_provider(no_proxy, proxy_file, proxy_list_url,
                                           proxy_cache)
    run_online_sync(
        input_path, db, dossier_dir, output,
        fmt=fmt, fields=_split_fields(fields),
        concurrency=concurrency, render_concurrency=render_concurrency,
        do_render=not no_render,
        maxmind_city=maxmind_city, maxmind_asn=maxmind_asn,
        abuse_key=abuse_key, cf_token=cf_token,
        ipthreat_paths=_expand_paths(ipthreat) if ipthreat else None,
        proxy_provider=proxy_provider, max_proxy_attempts=max_proxy_attempts,
        force=set(force),
    )
```

- [ ] **Step 5: Add the `check` command**

Add this new command after `run_online_cmd` (before the `fields` command at `domain_enrich/cli.py:410`):

```python
@cli.command(name="check")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True),
              help="Resource list: one domain/URL/IP per line.")
@click.option("--success", "success_path", required=True, type=click.Path(),
              help="TSV output for reachable resources.")
@click.option("--failed", "failed_path", required=True, type=click.Path(),
              help="TSV output for unreachable resources.")
@click.option("--concurrency", default=100, show_default=True,
              help="Concurrent checks.")
@click.option("--timeout", default=15.0, show_default=True,
              help="Per-request timeout (seconds).")
@click.option("--no-proxy", is_flag=True, default=False,
              help="Disable SOCKS5 proxy fallback on connection failure.")
@click.option("--proxy-list-url", multiple=True,
              help="SOCKS5 proxy-list URL (repeatable). Default: iplocate+proxifly.")
@click.option("--proxy-file", type=click.Path(),
              help="Use a local SOCKS5 proxy file instead of downloading.")
@click.option("--proxy-cache", envvar="DE_PROXY_CACHE",
              default="work/proxies-socks5.txt", show_default=True, type=click.Path(),
              help="Where to cache the fetched proxy list. Env: DE_PROXY_CACHE")
@click.option("--max-proxy-attempts", default=25, show_default=True,
              help="Max proxy retries per resource before marking it failed.")
def check_cmd(input_path, success_path, failed_path, concurrency, timeout,
              no_proxy, proxy_list_url, proxy_file, proxy_cache, max_proxy_attempts):
    """Check resource availability; write reachable/unreachable TSV files.

    Each resource is probed directly first; on a connection failure it is
    retried through SOCKS5 proxies (disable with --no-proxy). "Reachable" means
    any HTTP response was received.
    """
    from .online.checker import run_check_sync
    proxy_provider = _build_proxy_provider(no_proxy, proxy_file, proxy_list_url,
                                           proxy_cache)
    summary = run_check_sync(
        input_path, success_path, failed_path,
        concurrency=concurrency, proxy_provider=proxy_provider,
        max_proxy_attempts=max_proxy_attempts, timeout=timeout)
    click.echo(f"checked {summary['checked']}: {summary['ok']} ok, "
               f"{summary['failed']} failed")
```

- [ ] **Step 6: Run the CLI test to verify it passes**

Run: `python -m pytest tests/test_cli_lookup.py::test_check_command_is_wired -v`
Expected: PASS. (Monkeypatched `run_check_sync`; verifies wiring + `--no-proxy`/`--max-proxy-attempts` plumbing, no network.)

- [ ] **Step 7: Document in `README.md`**

Find the section describing the online runner / `run-online` (search README for `run-online`). Add a short subsection after it:

```markdown
### Proxy fallback & availability checker

Page rendering retries through public SOCKS5 proxies when a site is unreachable
(up to 25 attempts per domain; proxy use is logged to stderr). Lists are pulled
from iplocate and proxifly and cached under `work/proxies-socks5.txt`.

    # disable, or point at your own list:
    domain-enrich run-online --input /input/domains.txt --db /work/work.db --no-proxy
    domain-enrich run-online --input /input/domains.txt --db /work/work.db \
        --proxy-file /data/socks5.txt --max-proxy-attempts 10

Check reachability of a list of resources (same proxy pool on failure):

    domain-enrich check --input /input/resources.txt \
        --success /work/reachable.tsv --failed /work/unreachable.tsv

`reachable.tsv`: `resource  status  final_url  via_proxy`.
`unreachable.tsv`: `resource  attempts  error`.
```

- [ ] **Step 8: Run the entire test suite**

Run: `python -m pytest -q`
Expected: PASS (all tests, including the new `test_proxy.py`, `test_checker.py`, render/e2e/cli additions).

- [ ] **Step 9: Commit** *(pause for user go-ahead per COMMIT GATE)*

```bash
git add domain_enrich/cli.py tests/test_cli_lookup.py README.md
git commit -m "feat(cli): add check command + proxy options on run-online"
```

---

## Self-Review

**Spec coverage:**
- Proxy sources (both URLs, fallback order) → Task 1 (`DEFAULT_PROXY_URLS`, `_fetch_all`).
- Parse both line formats → Task 1 `parse_proxies`.
- Disk cache + TTL + stale fallback → Task 1.
- Render uses proxy on failure, ≤25 attempts, logs usage → Task 2.
- Per-context Chromium proxy launch → Task 4.
- `page_proxy` in dossier, no new DB/parquet columns → Task 4.
- Checker: input list, same proxies, two output files → Task 3.
- Checker HTTP semantics (any response = available, HEAD→GET) → Task 3.
- `httpx[socks]` dependency → Task 3.
- CLI `check` + `run-online` proxy options → Task 5.
- Docs → Task 5.
- Tests without real network/browser → every task.

**Placeholder scan:** none — all code blocks are complete.

**Type consistency:** `acquire()` returns `socks5://host:port` (Tasks 1/2/3 agree). `render_page` returns `page_proxy` (Tasks 2/4 agree). `check_resource`/`run_check` dict keys consistent between Task 3 impl and writers. `_build_proxy_provider` signature consistent between Tasks 5 call sites. `proxy_provider`/`max_proxy_attempts` kwargs consistent across Tasks 2/4/5.
