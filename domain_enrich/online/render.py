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
