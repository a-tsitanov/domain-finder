"""Live GeoIP + ASN.

Two interchangeable backends, cached by IP:

* **MaxMind** (default, no rate limit): reuse the offline ``.mmdb`` readers for
  O(1) local lookups — the fast path for large lists.
* **ip-api.com** (fallback, no key): one HTTP call per IP, hard-limited to
  45 req/min by a shared rate limiter.

Both return the same flat geo/ASN columns.
"""

from __future__ import annotations

import re
from typing import Dict, Optional

from ..sources.maxmind import lookup_ip as _mmdb_lookup
from .http import get_json
from .ratelimit import RateLimiter

IPAPI_BASE = "http://ip-api.com"
_IPAPI_FIELDS = "status,countryCode,city,lat,lon,as,asname,org"
_AS_RE = re.compile(r"AS(\d+)\s*(.*)", re.IGNORECASE)


def from_mmdb(city_reader, asn_reader, ip: str) -> Dict[str, object]:
    """Local MaxMind lookup; returns flat geo columns (may be empty)."""
    return _mmdb_lookup(city_reader, asn_reader, ip)


def _parse_ipapi(data: Optional[dict]) -> Dict[str, object]:
    if not isinstance(data, dict) or data.get("status") != "success":
        return {}
    out: Dict[str, object] = {}
    if data.get("countryCode"):
        out["geo_country"] = data["countryCode"]
    if data.get("city"):
        out["geo_city"] = data["city"]
    if data.get("lat") is not None:
        out["geo_lat"] = data["lat"]
    if data.get("lon") is not None:
        out["geo_lon"] = data["lon"]
    m = _AS_RE.match(str(data.get("as") or ""))
    if m:
        out["asn"] = int(m.group(1))
        org = data.get("asname") or m.group(2) or data.get("org")
        if org:
            out["asn_org"] = org
    elif data.get("asname"):
        out["asn_org"] = data["asname"]
    return out


async def from_ipapi(client, ip: str,
                     limiter: Optional[RateLimiter] = None) -> Dict[str, object]:
    if limiter is not None:
        await limiter.acquire()
    data = await get_json(client, f"{IPAPI_BASE}/json/{ip}",
                          params={"fields": _IPAPI_FIELDS})
    return _parse_ipapi(data)


async def lookup(ip: str, *, city_reader=None, asn_reader=None, client=None,
                 limiter: Optional[RateLimiter] = None) -> Dict[str, object]:
    """Resolve geo/ASN for ``ip`` using MaxMind if available, else ip-api."""
    if city_reader is not None or asn_reader is not None:
        data = from_mmdb(city_reader, asn_reader, ip)
        if data:
            return data
    if client is not None:
        return await from_ipapi(client, ip, limiter)
    return {}
