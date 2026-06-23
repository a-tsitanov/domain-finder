"""Tests for the online (live) enrichment mode.

Everything runs without real network or a real browser: httpx uses a
MockTransport, DNS/TLS/Playwright are fakes injected into the adapters.
"""

from __future__ import annotations

import gzip
import json
import os

import httpx
import pytest

from domain_enrich.online import (cache, dns_live, dossier, geo_live,
                                   netwhois_live, ratelimit, rdap_live,
                                   render as render_mod, threat_live, tls_live)
from domain_enrich.online.runner import lookup_online, run_online
from domain_enrich.online.writer import AsyncWriter
from domain_enrich.store import Store


# -- fakes ---------------------------------------------------------------
class FakeRdata:
    def __init__(self, text=None, **attrs):
        self._text = text
        for k, v in attrs.items():
            setattr(self, k, v)

    def __str__(self):
        return self._text


class FakeResolver:
    """Returns canned answers keyed by (name, rdtype)."""

    def __init__(self, answers):
        self.answers = answers

    async def resolve(self, name, rdtype):
        name = str(name).rstrip(".")
        key = (name, rdtype)
        if key not in self.answers:
            raise Exception("NoAnswer")
        return self.answers[key]


class FakePage:
    def __init__(self, html, status=200, url="https://example.com/"):
        self._html, self._status, self._url = html, status, url

    async def goto(self, url, timeout=None, wait_until=None):
        return type("Resp", (), {"status": self._status})()

    async def content(self):
        return self._html

    @property
    def url(self):
        return self._url

    async def close(self):
        pass


class FakeBrowser:
    def __init__(self, html="<html><body>hi</body></html>"):
        self.html = html
        self.pages = 0

    async def new_page(self):
        self.pages += 1
        return FakePage(self.html)


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


def mock_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# -- ratelimit -----------------------------------------------------------
async def test_ratelimit_unlimited_returns_immediately():
    rl = ratelimit.RateLimiter(0)
    assert rl.unlimited
    await rl.acquire()  # must not block


async def test_ratelimit_refills_with_injected_clock():
    t = {"now": 0.0}
    rl = ratelimit.RateLimiter(60, per=60.0, loop_time=lambda: t["now"])
    for _ in range(60):
        await rl.acquire()           # drains the bucket without waiting
    # Bucket empty now; advance the clock by 1s -> exactly 1 token back.
    t["now"] = 1.0
    rl._refill()
    assert rl._tokens >= 1


# -- cache (single-flight) ----------------------------------------------
async def test_cache_single_flight():
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        return "v"

    import asyncio
    c = cache.AsyncCache()
    results = await asyncio.gather(*[c.get("k", factory) for _ in range(10)])
    assert results == ["v"] * 10
    assert calls["n"] == 1          # all 10 misses coalesced into one call
    assert "k" in c


# -- dns_live ------------------------------------------------------------
async def test_dns_live_resolves_records_and_ptr():
    answers = {
        ("ex.com", "A"): [FakeRdata("1.2.3.4")],
        ("ex.com", "NS"): [FakeRdata(target="ns1.ex.com.")],
        ("ex.com", "MX"): [FakeRdata(exchange="mail.ex.com.")],
        ("ex.com", "TXT"): [FakeRdata(strings=[b"v=spf1"])],
        ("ex.com", "SOA"): [FakeRdata(mname="ns1.ex.com.")],
        ("4.3.2.1.in-addr.arpa", "PTR"): [FakeRdata("host.ex.com.")],
    }
    out = await dns_live.resolve("ex.com", FakeResolver(answers))
    assert out["a"] == ["1.2.3.4"]
    assert out["ns"] == ["ns1.ex.com"]
    assert out["mx"] == ["mail.ex.com"]
    assert out["txt"] == ["v=spf1"]
    assert out["soa"] == "ns1.ex.com"
    assert out["ips"] == ["1.2.3.4"]
    assert out["ptr"] == ["host.ex.com"]


# -- tls_live ------------------------------------------------------------
async def test_tls_live_captures_cipher_and_sans():
    async def opener(host, port, ctx, timeout):
        return {"cipher": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3",
                "sans": ["example.com", "www.example.com"]}

    out = await tls_live.handshake("example.com", opener=opener)
    assert out["tls"]["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert out["tls"]["sans"] == ["example.com", "www.example.com"]


async def test_tls_live_unreachable_returns_empty():
    async def opener(host, port, ctx, timeout):
        raise OSError("refused")

    assert await tls_live.handshake("nope.invalid", opener=opener) == {}


# -- rdap_live / netwhois_live ------------------------------------------
async def test_rdap_live_parses_registrar():
    def handler(request):
        return httpx.Response(200, json={
            "ldhName": "example.com",
            "entities": [{"roles": ["registrar"], "vcardArray":
                          ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
            "events": [{"eventAction": "registration",
                        "eventDate": "1997-09-15T04:00:00Z"}],
        })

    async with mock_client(handler) as client:
        out = await rdap_live.fetch_domain(client, "example.com")
    assert out["registrar"] == "Example Registrar"
    assert out["created_date"].startswith("1997-09-15")


async def test_netwhois_live_parses_ip_rdap():
    def handler(request):
        return httpx.Response(200, json={
            "handle": "NET-1-2-0-0-1",
            "startAddress": "1.2.0.0", "endAddress": "1.2.255.255",
            "name": "EXAMPLE-NET", "country": "US",
            "cidr0_cidrs": [{"v4prefix": "1.2.0.0", "length": 16}],
            "entities": [
                {"roles": ["registrant"], "vcardArray":
                 ["vcard", [["org", {}, "text", "Example ISP"]]]},
                {"roles": ["abuse"], "vcardArray":
                 ["vcard", [["email", {}, "text", "abuse@example.net"]]]},
            ],
        })

    async with mock_client(handler) as client:
        out = await netwhois_live.fetch_ip(client, "1.2.3.4")
    assert out["net_range"] == "1.2.0.0/16"
    assert out["net_name"] == "EXAMPLE-NET"
    assert out["net_org"] == "Example ISP"
    assert out["net_country"] == "US"
    assert out["net_abuse_email"] == "abuse@example.net"


# -- geo_live ------------------------------------------------------------
async def test_geo_live_ipapi_parse():
    def handler(request):
        return httpx.Response(200, json={
            "status": "success", "countryCode": "US", "city": "Mountain View",
            "lat": 37.4, "lon": -122.1, "as": "AS15169 Google LLC",
            "asname": "GOOGLE",
        })

    async with mock_client(handler) as client:
        out = await geo_live.lookup("8.8.8.8", client=client)
    assert out["geo_country"] == "US"
    assert out["asn"] == 15169
    assert out["asn_org"] == "GOOGLE"


def test_geo_live_mmdb_path():
    class FakeCity:
        def city(self, ip):
            loc = type("L", (), {"latitude": 1.0, "longitude": 2.0})()
            country = type("C", (), {"iso_code": "DE"})()
            city = type("Ci", (), {"name": "Berlin"})()
            return type("R", (), {"country": country, "city": city,
                                  "location": loc})()
    out = geo_live.from_mmdb(FakeCity(), None, "1.1.1.1")
    assert out["geo_country"] == "DE" and out["geo_city"] == "Berlin"


# -- threat_live ---------------------------------------------------------
async def test_threat_live_urlhaus_hit():
    def handler(request):
        if "urlhaus" in str(request.url):
            return httpx.Response(200, json={"query_status": "ok",
                                             "urls": [{"url": "http://x"}]})
        return httpx.Response(200, json={"query_status": "no_result"})

    async with mock_client(handler) as client:
        out = await threat_live.check(client, "bad.com", auth_key="K")
    assert out["threat_label"] == "malware"
    assert "urlhaus" in out["threat_sources"]


async def test_threat_live_no_key_skips():
    async with mock_client(lambda r: httpx.Response(500)) as client:
        assert await threat_live.check(client, "x.com") == {}


# -- render --------------------------------------------------------------
async def test_render_page_captures_html():
    out = await render_mod.render_page(FakeBrowser("<h1>hello</h1>"), "example.com")
    assert out["page_html"] == "<h1>hello</h1>"
    assert out["page_http_status"] == 200
    assert out["page_error"] is None
    assert out["page_bytes"] == len("<h1>hello</h1>".encode())


async def test_render_page_handles_failure():
    class Boom:
        async def new_page(self):
            raise RuntimeError("no browser")
    out = await render_mod.render_page(Boom(), "example.com")
    assert out["page_html"] is None
    assert "no browser" in out["page_error"]


# -- dossier -------------------------------------------------------------
def test_dossier_roundtrip(tmp_path):
    rec = {"domain": "ex.com", "a": "1.2.3.4", "page_html": "<html></html>"}
    path = dossier.write_dossier(str(tmp_path), "ex.com", rec)
    assert path.endswith("ex.com.dossier.gz")
    assert dossier.read_dossier(path) == rec
    assert dossier.dossier_complete(str(tmp_path), "ex.com")
    # really gzip
    with gzip.open(path, "rb") as fh:
        assert json.loads(fh.read())["domain"] == "ex.com"


# -- writer --------------------------------------------------------------
async def test_async_writer_batches(tmp_path):
    db = str(tmp_path / "w.db")
    async with AsyncWriter(lambda: Store(db), batch_size=2) as w:
        await w.call(lambda s: s.add_domains([("a.com", "a.com"), ("b.com", "b.com")]))
        await w.submit(lambda s: s.update_geo("a.com", geo_country="US"))
        await w.submit(lambda s: s.update_geo("b.com", geo_country="DE"))  # flush
        await w.flush()
        rows = await w.call(lambda s: {r["domain"]: r["geo_country"]
                                       for r in s.iter_rows()})
    assert rows == {"a.com": "US", "b.com": "DE"}


# -- end-to-end runner ---------------------------------------------------
def _e2e_handler(request):
    url = str(request.url)
    if "/domain/" in url:
        return httpx.Response(200, json={
            "ldhName": "example.com",
            "entities": [{"roles": ["registrar"], "vcardArray":
                          ["vcard", [["fn", {}, "text", "RegCo"]]]}]})
    if "/ip/" in url:
        return httpx.Response(200, json={
            "startAddress": "1.2.0.0", "endAddress": "1.2.255.255",
            "name": "NET", "country": "US"})
    if "ip-api.com" in url:
        return httpx.Response(200, json={"status": "success", "countryCode": "US",
                                         "as": "AS64500 Test"})
    return httpx.Response(404)


def _resolver():
    return FakeResolver({
        ("example.com", "A"): [FakeRdata("1.2.3.4")],
        ("test.org", "A"): [FakeRdata("1.2.3.4")],   # same IP -> cache hit
    })


async def test_run_online_e2e(tmp_path):
    inp = tmp_path / "domains.txt"
    inp.write_text("example.com\ntest.org\n")
    db = str(tmp_path / "work.db")
    dossiers = str(tmp_path / "dossiers")
    out = str(tmp_path / "agg.parquet")

    async with mock_client(_e2e_handler) as client:
        res = await run_online(
            str(inp), db, dossiers, out, fmt="parquet",
            concurrency=4, do_render=True,
            client=client, resolver=_resolver(), browser=FakeBrowser("<p>ok</p>"))
    assert res["parquet"] == 2

    # Per-domain dossiers exist, contain page_html + enrichment.
    d = dossier.read_dossier(os.path.join(dossiers, "example.com.dossier.gz"))
    assert d["page_html"] == "<p>ok</p>"
    assert d["registrar"] == "RegCo"
    assert d["net_name"] == "NET"
    assert d["geo_country"] == "US"
    assert d["a"] == "1.2.3.4"
    assert os.path.exists(os.path.join(dossiers, "test.org.dossier.gz"))

    # Aggregate parquet excludes page_html.
    import pyarrow.parquet as pq
    cols = pq.read_table(out).column_names
    assert "page_html" not in cols
    assert "page_http_status" in cols

    # Resume: second run finds nothing pending and rewrites nothing new.
    async with mock_client(_e2e_handler) as client:
        res2 = await run_online(
            None, db, dossiers, out, fmt="parquet", client=client,
            resolver=_resolver(), browser=FakeBrowser("<p>SHOULD NOT APPEAR</p>"))
    d2 = dossier.read_dossier(os.path.join(dossiers, "example.com.dossier.gz"))
    assert d2["page_html"] == "<p>ok</p>"   # unchanged -> resume skipped it


async def test_run_online_force_reprocesses(tmp_path):
    inp = tmp_path / "domains.txt"
    inp.write_text("example.com\n")
    db = str(tmp_path / "work.db")
    dossiers = str(tmp_path / "dossiers")

    async with mock_client(_e2e_handler) as client:
        await run_online(str(inp), db, dossiers, None, do_render=True,
                         client=client, resolver=_resolver(),
                         browser=FakeBrowser("<p>v1</p>"))
    # Remove dossier so file-resume won't short-circuit, force the stage.
    os.remove(os.path.join(dossiers, "example.com.dossier.gz"))
    async with mock_client(_e2e_handler) as client:
        await run_online(None, db, dossiers, None, do_render=True,
                         force={"online"}, client=client, resolver=_resolver(),
                         browser=FakeBrowser("<p>v2</p>"))
    d = dossier.read_dossier(os.path.join(dossiers, "example.com.dossier.gz"))
    assert d["page_html"] == "<p>v2</p>"


async def test_lookup_online_single_domain():
    async with mock_client(_e2e_handler) as client:
        row = await lookup_online("example.com", client=client,
                                  resolver=_resolver(), do_render=False)
    assert row["registrar"] == "RegCo"
    assert row["geo_country"] == "US"
    assert row["page_html"] is None


# -- proxy fallback tests ------------------------------------------------
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
