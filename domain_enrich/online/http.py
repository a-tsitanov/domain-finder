"""Shared async HTTP helpers for the online adapters.

A single ``httpx.AsyncClient`` (pooled connections, HTTP/2) is shared across
RDAP, ip-api, abuse.ch and Cloudflare. ``get_json`` adds small bounded retries
with jittered backoff for transient errors and 429s.
"""

from __future__ import annotations

import asyncio
from typing import Optional

USER_AGENT = "domain-enrich/online (+https://github.com/; research)"


def make_client(timeout: float = 15.0, **kwargs):
    import httpx
    limits = httpx.Limits(max_connections=200, max_keepalive_connections=50)
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        limits=limits,
        **kwargs,
    )


async def get_json(client, url: str, *, retries: int = 2, backoff: float = 0.5,
                   params: Optional[dict] = None, headers: Optional[dict] = None,
                   ok_404: bool = True):
    """GET ``url`` and return parsed JSON, or ``None``.

    Returns ``None`` for 404 (when ``ok_404``) and after exhausting retries on
    transient failures. Raises nothing the caller must handle — adapters treat
    ``None`` as "no data".
    """
    attempt = 0
    while True:
        try:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 404 and ok_404:
                return None
            if resp.status_code == 429 or resp.status_code >= 500:
                raise _Retry(resp.status_code)
            if resp.status_code >= 400:
                return None
            return resp.json()
        except Exception:
            if attempt >= retries:
                return None
            await asyncio.sleep(backoff * (2 ** attempt) + 0.01 * attempt)
            attempt += 1


class _Retry(Exception):
    pass
