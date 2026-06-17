"""Live domain RDAP (domain whois).

Fetches the RDAP object for a domain from ``rdap.org`` (which bootstraps to the
authoritative registry/registrar server) and parses it with the existing
offline parser :func:`domain_enrich.sources.rdap.parse_rdap`. Only the data
acquisition is online; the parsing is shared with the offline mode.
"""

from __future__ import annotations

from typing import Dict, Optional

from ..sources.rdap import parse_rdap
from .http import get_json
from .ratelimit import RateLimiter

RDAP_BASE = "https://rdap.org"


async def fetch_domain(client, domain: str, limiter: Optional[RateLimiter] = None,
                       base: str = RDAP_BASE) -> Dict[str, object]:
    """Return flat domain-whois columns for ``domain`` (or ``{}``)."""
    if limiter is not None:
        await limiter.acquire()
    doc = await get_json(client, f"{base}/domain/{domain}")
    if not isinstance(doc, dict):
        return {}
    return parse_rdap(doc)
