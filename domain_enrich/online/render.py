"""Rendered-page download via Playwright (async).

Navigates a headless Chromium page to the domain, waits for the DOM to settle
after JS, and captures the full rendered HTML plus metadata (final URL, HTTP
status, byte size). No analysis — the HTML is returned verbatim for storage.

``render_page`` operates on a minimal browser surface (``new_page`` →
``goto``/``content``/``close``) so tests can pass a fake browser without a real
Chromium.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def render_page(browser, domain: str, *, timeout_ms: int = 20000,
                      wait_until: str = "load") -> Dict[str, object]:
    """Render ``https://<domain>`` (fallback ``http://``) and return page data.

    Returns a dict with ``page_html`` (str or None), ``page_http_status``,
    ``page_final_url``, ``page_bytes``, ``page_fetched_at`` and ``page_error``.
    Never raises: failures land in ``page_error``.
    """
    last_error: Optional[str] = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        page = None
        try:
            page = await browser.new_page()
            response = await page.goto(url, timeout=timeout_ms, wait_until=wait_until)
            html = await page.content()
            status = response.status if response is not None else None
            final_url = page.url
            return {
                "page_html": html,
                "page_http_status": status,
                "page_final_url": final_url,
                "page_bytes": len(html.encode("utf-8")) if html else 0,
                "page_fetched_at": _now_iso(),
                "page_error": None,
            }
        except Exception as exc:  # noqa: BLE001 - record and try next scheme
            last_error = f"{type(exc).__name__}: {exc}"
        finally:
            if page is not None:
                try:
                    await page.close()
                except Exception:
                    pass

    return {
        "page_html": None,
        "page_http_status": None,
        "page_final_url": None,
        "page_bytes": 0,
        "page_fetched_at": _now_iso(),
        "page_error": last_error or "render failed",
    }
