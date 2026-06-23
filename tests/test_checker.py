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


async def test_500_response_is_available():
    def handler_for(proxy):
        return lambda req: httpx.Response(500, request=req)
    res = await check_resource(_factory(handler_for), "example.com")
    assert res["ok"] is True
    assert res["status"] == 500
    assert res["via_proxy"] is None
    assert res["attempts"] == 0


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
