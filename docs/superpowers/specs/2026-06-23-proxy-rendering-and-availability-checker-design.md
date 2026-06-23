# Proxy-aware rendering + resource availability checker

**Date:** 2026-06-23
**Status:** Approved (design)

## Problem

The current online mode renders pages with a headless Chromium that always
connects directly. Some sites are unreachable from the runner's network and the
render simply fails (`page_error`), with no second chance. Two capabilities are
needed:

1. **Proxy fallback in rendering.** When a page is unavailable or the connection
   errors, retry the render through SOCKS5 proxies pulled from a public list, up
   to **25** attempts per domain, logging every proxy use.
2. **Resource availability checker.** A standalone tool that takes a list of
   resources, checks reachability (using the *same* proxy pool on failure) and
   writes **two** output files: successful connections and failed ones.

## Proxy sources

Public SOCKS5 lists, tried in order (first that downloads wins):

1. `https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt`
2. `https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt`

Line formats differ between sources (`host:port` vs `socks5://host:port`); the
parser strips an optional `socks5://` scheme and keeps `host:port`, dropping any
line that does not look like `host:port`.

## Architecture

Three units, all under `domain_enrich/online/`, plus CLI wiring.

### `proxy.py` — `ProxyProvider`

Shared by both features. Responsibilities:

- **Fetch:** download from the configured URLs in order; first success wins.
  The HTTP fetch function is injectable for tests (no real network).
- **Parse:** strip optional `socks5://`, validate `host:port`, dedupe.
- **Disk cache:** cache parsed proxies to a file (default `work/proxies-socks5.txt`,
  override via `DE_PROXY_CACHE` env or `--proxy-cache`). TTL default **6h**. On
  load: fresh cache → read from disk; stale/absent → fetch + rewrite cache; if
  fetch fails but a (stale) cache exists, fall back to it. A clock function is
  injectable for TTL tests.
- **Rotation:** `async acquire() -> str | None` returns the next proxy as
  `socks5://host:port`. The pool is shuffled once, then served round-robin.
  Returns `None` when the pool is empty.
- **`ensure_loaded()`:** single-flight async load (fetch-or-cache) performed once
  per process; concurrent callers coalesce.
- Construction options: `urls: list[str]`, `cache_path: str | None`,
  `ttl_seconds: float`, `local_file: str | None` (use a file verbatim instead of
  fetching), plus injected `fetcher` and `now` for tests.

Defaults live as module constants: `DEFAULT_PROXY_URLS`, `DEFAULT_TTL_SECONDS = 6*3600`.

### `render.py` — proxy fallback

New signature:

```python
async def render_page(browser, domain, *, timeout_ms=20000, wait_until="load",
                      proxy_provider=None, max_proxy_attempts=25, log=None) -> dict
```

Behaviour:

- **Happy path unchanged.** Try `https://` then `http://` on the default context
  via `browser.new_page()` (no proxy). On success, return the existing dict shape
  with `page_proxy = None`.
- **Proxy fallback.** If both schemes fail *and* `proxy_provider` is set, loop up
  to `max_proxy_attempts` (default 25): take `proxy = await provider.acquire()`
  (stop early if `None`), open `ctx = await browser.new_context(proxy={"server": proxy})`,
  open a page in it, try `https://` then `http://`, close the context. First
  success returns the page dict with `page_proxy = proxy`. Every attempt is logged
  via `log` (falls back to module stderr logger) as
  `[proxy] <domain> attempt k/25 via <proxy>: <ok|ErrorType: msg>`.
- **Never raises.** After exhausting attempts, return the failure dict
  (`page_html=None`, `page_error=<last error>`, `page_proxy=None`).
- Returned dict gains one key, `page_proxy` (str | None), in addition to the
  existing `page_html`, `page_http_status`, `page_final_url`, `page_bytes`,
  `page_fetched_at`, `page_error`.

No new persisted DB/parquet columns. `runner.py` already strips `page_html` from
`page` and copies only `_PAGE_META` into the row; it will additionally copy
`page_proxy` straight into the JSON dossier record (`record["page_proxy"]`),
leaving `store.py`/`export.py` untouched. The stderr log satisfies the "log proxy
usage" requirement.

To allow per-context proxies in Chromium, the browser must be launched with
`proxy={"server": "per-context"}` — done in `runner.py` (and `lookup_online`) when
proxy fallback is enabled. Tests inject a fake browser, so the real launch is not
exercised there.

### `checker.py` — availability checker

```python
async def check_resource(client_factory, resource, *, proxy_provider,
                         max_proxy_attempts=25, timeout=15.0, log=None) -> dict
async def run_check(input_path, success_path, failed_path, *, concurrency=100,
                    proxy_provider, max_proxy_attempts=25, timeout=15.0) -> dict
```

- **URL building:** if `resource` already has a scheme, use it; else try
  `https://<resource>` then `http://<resource>`.
- **Check semantics:** *available = an HTTP response was received* (the connection
  succeeded), regardless of status code. The status is recorded. A connection
  error / timeout / DNS failure means unreachable.
- **Direct first:** issue `HEAD`; if the server rejects HEAD (405 / 501) retry the
  same URL with `GET`. `follow_redirects=True`.
- **Proxy fallback:** on a connection-level failure, loop the proxy pool up to
  `max_proxy_attempts`, each attempt using an httpx client bound to that SOCKS5
  proxy (`httpx.AsyncClient(proxies=proxy)` / `proxy=` per httpx version). Log each
  attempt like the renderer.
- **Result dict:** `{resource, ok: bool, status: int|None, final_url: str|None,
  via_proxy: str|None, attempts: int, error: str|None}`.
- **`run_check`:** read resources line-by-line from `input_path` (verbatim, *not*
  normalized — may be a domain, URL or IP; blank lines skipped). Drain a queue
  with a worker pool of size `concurrency` (mirrors `runner.py`). Write two TSV
  files with a header row each:
  - `success.tsv`: `resource\tstatus\tfinal_url\tvia_proxy`
  - `failed.tsv`: `resource\tattempts\terror`
  Return a summary `{"checked": n, "ok": x, "failed": y}`.

`httpx` SOCKS5 support needs the `socksio` package → add `httpx[socks]` to the
`[online]` optional dependencies (the online Docker image installs `.[online]`).

### CLI (`cli.py`)

New command:

```
domain-enrich check --input LIST --success OUT_OK --failed OUT_FAIL
    [--concurrency 100] [--timeout 15] [--max-proxy-attempts 25]
    [--no-proxy] [--proxy-file FILE] [--proxy-list-url URL ...] [--proxy-cache PATH]
```

`run-online` gains the same proxy options: `--max-proxy-attempts` (default 25),
`--no-proxy`, `--proxy-list-url` (repeatable; defaults to the two URLs above),
`--proxy-file`, `--proxy-cache` (env `DE_PROXY_CACHE`). Proxy fallback in rendering
is **on by default**.

### `runner.py` wiring

`run_online` gains: `use_proxy=True`, `proxy_urls=None` (→ defaults),
`proxy_file=None`, `proxy_cache=None`, `max_proxy_attempts=25`. When
`do_render and use_proxy`: build a `ProxyProvider`, `await ensure_loaded()`, launch
Chromium with `proxy={"server": "per-context"}`, and thread `proxy_provider` +
`max_proxy_attempts` through `_process_domain` → `render_page`. `lookup_online`
gets the same optional support for `--render`. The provider is injectable so the
e2e test can pass a fake (or `None`).

## Testing (no real network or browser)

Match the style of `tests/test_online.py` (fakes + httpx `MockTransport`).

- **`proxy.py`** (`tests/test_proxy.py`): parse both line formats + scheme strip +
  junk rejection; round-robin rotation; disk-cache write/read; TTL expiry with an
  injected clock; fetch-failure falls back to stale cache; URL fallback order.
- **`render.py`** (extend `tests/test_online.py`): direct failure → success via a
  proxy context (extend `FakeBrowser` with `new_context` returning a context whose
  `new_page` yields a `FakePage`); attempt cap honored (≤ 25); each attempt logged;
  `proxy_provider=None` → unchanged behaviour and `page_proxy=None`.
- **`checker.py`** (`tests/test_checker.py`): direct success; direct failure →
  proxy success; total failure after N attempts; HEAD→GET fallback on 405; TSV
  file contents (headers + rows) for a mixed input.

## Defaults summary

| Setting | Default |
| --- | --- |
| Proxy URLs | iplocate socks5, then proxifly socks5 |
| Cache path | `work/proxies-socks5.txt` (env `DE_PROXY_CACHE`) |
| Cache TTL | 6 hours |
| Max proxy attempts | 25 |
| Render proxy fallback | on (disable with `--no-proxy`) |
| Checker "available" | any HTTP response received |
| Checker concurrency | 100 |
| Checker timeout | 15s |

## Out of scope

- HTTP/HTTPS/SOCKS4 proxy protocols (SOCKS5 only, per the source lists).
- Proxy health scoring / persistent good-proxy ranking (simple round-robin only).
- New persisted parquet/SQLite columns for proxy metadata.
