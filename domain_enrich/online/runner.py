"""Async orchestrator for the online enrichment mode.

A pool of ``concurrency`` worker coroutines drains a queue of domains; each
worker runs one domain end-to-end through the live chain
(dns → tls → rdap → geo → netwhois → threat → popularity → render), writes its
``<domain>.dossier.gz`` and submits a single batched DB update. Rendering is
capped by its own (smaller) semaphore because it is RAM-bound. IP- and
ASN-keyed lookups are de-duplicated through shared single-flight caches.

All network/browser dependencies are injectable so the whole run is testable
without real network access or a real Chromium.
"""

from __future__ import annotations

import asyncio
import sys
from typing import List, Optional, Sequence, Set, Tuple

from ..export import FLAT_FIELDS, export as export_table, flatten_row
from ..store import Store
from . import (dns_live, geo_live, netwhois_live, popularity_live, rdap_live,
               render as render_mod, threat_live, tls_live)
from .cache import AsyncCache
from .dossier import dossier_complete, dossier_path, write_dossier
from .http import make_client
from .ratelimit import RateLimiter
from .writer import AsyncWriter

# Terminal per-row flag: a row with s_render set has finished online processing
# (whether or not a page was actually rendered). Resume skips it.
ONLINE_FLAGS = ("s_odns", "s_otls", "s_ordap", "s_onet", "s_ogeo",
                "s_othreat", "s_opop", "s_render")
_PAGE_META = ("page_path", "page_http_status", "page_final_url",
              "page_bytes", "page_fetched_at", "page_error")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _normalize_into(store, input_path: str, chunk: int = 10000) -> int:
    from ..normalize import read_input
    total, buf = 0, []
    for pair in read_input(input_path):
        buf.append(pair)
        if len(buf) >= chunk:
            total += store.add_domains(buf)
            buf = []
    if buf:
        total += store.add_domains(buf)
    return total


def _build_raw_row(domain, original, dns, tls, geo, net, rdap, threat, pop,
                   page_meta) -> dict:
    """Assemble a raw store-shaped row for flatten_row / dossier output."""
    raw = {
        "domain": domain, "original": original,
        "a": dns.get("a"), "aaaa": dns.get("aaaa"), "ns": dns.get("ns"),
        "mx": dns.get("mx"), "txt": dns.get("txt"), "cname": dns.get("cname"),
        "ptr": dns.get("ptr"), "ips": dns.get("ips"), "soa": dns.get("soa"),
        "tls": tls.get("tls"),
        "nameservers": rdap.get("nameservers"),
    }
    raw.update(geo)
    raw.update(net)
    raw.update({k: v for k, v in rdap.items() if k != "nameservers"})
    raw.update(threat)
    raw.update(pop)
    raw.update(page_meta)
    return raw


async def _process_domain(domain, original, *, client, resolver, browser,
                          city_reader, asn_reader, geo_cache, net_cache,
                          ip_matcher, abuse_key, cf_token, do_render,
                          dossier_dir, limiters, render_sem,
                          proxy_provider=None, max_proxy_attempts=25) -> dict:
    """Run the full live chain for one domain; return its flat dossier record."""
    dns = await dns_live.resolve(domain, resolver)
    ips: List[str] = list(dns.get("ips") or [])

    tls = await tls_live.handshake(domain)
    rdap = await rdap_live.fetch_domain(client, domain, limiters["rdap"])

    geo: dict = {}
    net: dict = {}
    for ip in ips:
        if not geo:
            geo = await geo_cache.get(
                ("geo", ip),
                lambda ip=ip: geo_live.lookup(
                    ip, city_reader=city_reader, asn_reader=asn_reader,
                    client=client, limiter=limiters["ipapi"]),
            )
        if not net:
            net = await net_cache.get(
                ("net", ip),
                lambda ip=ip: netwhois_live.fetch_ip(client, ip, limiters["rdap"]),
            )
        if geo and net:
            break

    threat = await threat_live.check(client, domain, ips, abuse_key,
                                     limiters["abuse"], ip_matcher)
    pop = await popularity_live.fetch_rank(client, domain, cf_token,
                                           limiters["cf"])

    page: dict = {}
    if do_render and browser is not None:
        async with render_sem:
            page = await render_mod.render_page(
                browser, domain, proxy_provider=proxy_provider,
                max_proxy_attempts=max_proxy_attempts)

    page_html = page.pop("page_html", None) if page else None
    page_meta = {k: page.get(k) for k in _PAGE_META}
    if dossier_dir:
        page_meta["page_path"] = dossier_path(dossier_dir, domain)

    raw = _build_raw_row(domain, original, dns, tls, geo, net, rdap, threat,
                         pop, page_meta)
    record = flatten_row(raw)
    record["page_html"] = page_html
    record["page_proxy"] = page.get("page_proxy") if page else None

    # Persist updates (buffered) — capture values for the writer thread.
    def db_op(store, d=domain, dns=dns, tls=tls, geo=geo, net=net, rdap=rdap,
              threat=threat, pop=pop, page_meta=page_meta):
        store.update_dns(d, a=dns.get("a"), aaaa=dns.get("aaaa"),
                         ns=dns.get("ns"), mx=dns.get("mx"), ips=dns.get("ips"),
                         tls=tls.get("tls"), txt=dns.get("txt"),
                         soa=dns.get("soa"), cname=dns.get("cname"),
                         ptr=dns.get("ptr"))
        if geo:
            store.update_geo(d, **geo)
        if net:
            store.update_netwhois(d, **net)
        if rdap:
            store.update_rdap(d, **rdap)
        if threat:
            store.update_threat(d, **threat)
        if pop:
            store.update_tranco(d, **pop)
        store.update_page(d, **page_meta)
        for flag in ONLINE_FLAGS:
            store.mark_row_done(d, flag)

    return {"domain": domain, "record": record, "db_op": db_op}


async def run_online(
    input_path: Optional[str],
    db: str,
    dossier_dir: str,
    output: Optional[str] = None,
    *,
    fmt: str = "both",
    fields: Optional[List[str]] = None,
    concurrency: int = 50,
    render_concurrency: int = 8,
    do_render: bool = True,
    maxmind_city: Optional[str] = None,
    maxmind_asn: Optional[str] = None,
    abuse_key: Optional[str] = None,
    cf_token: Optional[str] = None,
    ipthreat_paths: Optional[Sequence[str]] = None,
    force: Optional[Set[str]] = None,
    ipapi_rate: float = 45.0,
    # Injectable deps (tests / advanced use):
    client=None, resolver=None, browser=None,
    proxy_provider=None, max_proxy_attempts: int = 25,
    write_batch: int = 500,
) -> dict:
    force = set(force or [])

    writer = AsyncWriter(lambda: Store(db), batch_size=write_batch)
    await writer.start()

    # -- normalize -------------------------------------------------------
    if input_path:
        if "normalize" in force or not await writer.call(
                lambda s: s.stage_done("normalize")):
            n = await writer.call(lambda s: _normalize_into(s, input_path))
            await writer.call(lambda s: s.mark_stage("normalize", "done"))
            _log(f"[normalize] {n} new domains")

    # -- force resets ----------------------------------------------------
    reset = set(force)
    if "online" in reset or "render" in reset:
        reset |= set(ONLINE_FLAGS) | {f.lstrip("s_") for f in ONLINE_FLAGS}
    for flag in ONLINE_FLAGS:
        stage = flag[2:]  # s_odns -> odns
        if flag in reset or stage in reset or "online" in reset:
            await writer.call(lambda s, fl=flag: s.reset_flag(fl))

    # -- pending list (terminal flag s_render) ---------------------------
    pending: List[Tuple[str, str]] = await writer.call(
        lambda s: [(r["domain"], r["original"]) for r in s.iter_rows_pending("s_render")]
    )
    # Skip rows whose dossier already exists (file-level resume).
    if dossier_dir:
        pending = [(d, o) for d, o in pending if not dossier_complete(dossier_dir, d)]
    _log(f"[online] {len(pending)} domains to process "
         f"(concurrency={concurrency}, render={'on' if do_render else 'off'})")

    if not pending:
        results = await _finish(writer, output, fields, fmt)
        await writer.close()
        return results

    # -- shared resources ------------------------------------------------
    own_client = client is None
    if own_client:
        client = make_client()
    # ip-api only matters when MaxMind is absent.
    use_ipapi = not (maxmind_city or maxmind_asn)
    limiters = {
        "rdap": RateLimiter(0),                       # unlimited, concurrency-bound
        "ipapi": RateLimiter(ipapi_rate if use_ipapi else 0, 60.0),
        "abuse": RateLimiter(0),
        "cf": RateLimiter(0),
    }
    geo_cache, net_cache = AsyncCache(), AsyncCache()
    render_sem = asyncio.Semaphore(render_concurrency)

    city_reader = asn_reader = None
    ip_matcher = None
    own_browser = False
    pw = None
    try:
        import geoip2.database
        if maxmind_city:
            city_reader = geoip2.database.Reader(maxmind_city)
        if maxmind_asn:
            asn_reader = geoip2.database.Reader(maxmind_asn)
    except Exception as exc:  # noqa: BLE001
        _log(f"[online] MaxMind unavailable ({exc}); geo via ip-api")

    if ipthreat_paths:
        from ..sources.ipthreat import IpThreat
        ip_matcher = IpThreat()
        for p in ipthreat_paths:
            try:
                ip_matcher.add(p)
            except Exception:
                pass

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

    # -- worker pool -----------------------------------------------------
    queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 2)
    done_count = 0
    total = len(pending)

    async def worker():
        nonlocal done_count
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                return
            domain, original = item
            try:
                res = await _process_domain(
                    domain, original, client=client, resolver=resolver,
                    browser=browser, city_reader=city_reader,
                    asn_reader=asn_reader, geo_cache=geo_cache,
                    net_cache=net_cache, ip_matcher=ip_matcher,
                    abuse_key=abuse_key, cf_token=cf_token, do_render=do_render,
                    dossier_dir=dossier_dir, limiters=limiters,
                    render_sem=render_sem, proxy_provider=proxy_provider,
                    max_proxy_attempts=max_proxy_attempts)
                if dossier_dir:
                    await asyncio.to_thread(write_dossier, dossier_dir, domain,
                                            res["record"])
                await writer.submit(res["db_op"])
            except Exception as exc:  # noqa: BLE001 - never let one domain stall
                _log(f"[online] {domain}: {type(exc).__name__}: {exc}")

                def fail_op(store, d=domain, e=str(exc)):
                    store.update_page(d, page_error=f"process error: {e}")
                    for flag in ONLINE_FLAGS:
                        store.mark_row_done(d, flag)
                await writer.submit(fail_op)
            finally:
                done_count += 1
                if done_count % 500 == 0 or done_count == total:
                    _log(f"[online] {done_count}/{total}")
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    try:
        for item in pending:
            await queue.put(item)
        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers)
        await writer.flush()
    finally:
        if own_browser and browser is not None:
            try:
                await browser.close()
            except Exception:
                pass
        if pw is not None:
            try:
                await pw.stop()
            except Exception:
                pass
        for r in (city_reader, asn_reader):
            if r is not None:
                try:
                    r.close()
                except Exception:
                    pass
        if own_client and client is not None:
            await client.aclose()

    results = await _finish(writer, output, fields, fmt)
    await writer.close()
    _log(f"[online] done: {total} domains, dossiers in {dossier_dir}")
    return results


async def _finish(writer: AsyncWriter, output, fields, fmt) -> dict:
    """Write the aggregate parquet/CSV (page_html excluded) if requested."""
    if not output:
        return {}
    use_fields = fields or list(FLAT_FIELDS)
    return await writer.call(
        lambda s: export_table(s, output, fields=use_fields, fmt=fmt))


# -- single-domain live dossier (lookup --online) ------------------------
async def lookup_online(domain: str, *, maxmind_city=None, maxmind_asn=None,
                        abuse_key=None, cf_token=None, do_render=False,
                        proxy_provider=None, max_proxy_attempts=25,
                        client=None, resolver=None, browser=None) -> dict:
    """Enrich one domain live and return its flat record (no files written)."""
    from ..normalize import normalize_domain
    norm = normalize_domain(domain)
    if not norm:
        raise ValueError(f"not a valid domain: {domain!r}")

    own_client = client is None
    if own_client:
        client = make_client()
    city_reader = asn_reader = None
    try:
        import geoip2.database
        if maxmind_city:
            city_reader = geoip2.database.Reader(maxmind_city)
        if maxmind_asn:
            asn_reader = geoip2.database.Reader(maxmind_asn)
    except Exception:
        pass

    limiters = {"rdap": RateLimiter(0), "ipapi": RateLimiter(45, 60.0),
                "abuse": RateLimiter(0), "cf": RateLimiter(0)}
    try:
        res = await _process_domain(
            norm, domain, client=client, resolver=resolver, browser=browser,
            city_reader=city_reader, asn_reader=asn_reader,
            geo_cache=AsyncCache(), net_cache=AsyncCache(), ip_matcher=None,
            abuse_key=abuse_key, cf_token=cf_token, do_render=do_render,
            dossier_dir=None, limiters=limiters,
            render_sem=asyncio.Semaphore(1), proxy_provider=proxy_provider,
            max_proxy_attempts=max_proxy_attempts)
        return res["record"]
    finally:
        for r in (city_reader, asn_reader):
            if r is not None:
                try:
                    r.close()
                except Exception:
                    pass
        if own_client:
            await client.aclose()


def run_online_sync(*args, **kwargs) -> dict:
    return asyncio.run(run_online(*args, **kwargs))


def lookup_online_sync(*args, **kwargs) -> dict:
    return asyncio.run(lookup_online(*args, **kwargs))
