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
