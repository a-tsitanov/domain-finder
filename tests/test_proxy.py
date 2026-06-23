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
