"""Live network whois via IP RDAP.

Fetches the RDAP object for an IP from ``rdap.org`` (bootstraps to the owning
RIR: ARIN / RIPE / APNIC / …) and extracts the network range, netname, org,
country and abuse email — the same columns the offline RIR-dump stage filled.

Results are cached by IP via the orchestrator, so a network shared by many
domains is fetched once.
"""

from __future__ import annotations

from typing import Dict, Optional

from ..sources.rdap import _entities_by_role, _entity_email, _entity_name
from .http import get_json
from .ratelimit import RateLimiter

RDAP_BASE = "https://rdap.org"


def parse_ip_rdap(doc: Optional[dict]) -> Dict[str, object]:
    """Extract flat network-whois columns from an RDAP IP object."""
    if not isinstance(doc, dict) or not doc:
        return {}
    out: Dict[str, object] = {}

    # Range: prefer the CIDR form, else start-end.
    cidrs = doc.get("cidr0_cidrs")
    if isinstance(cidrs, list) and cidrs:
        c = cidrs[0]
        prefix = c.get("v4prefix") or c.get("v6prefix")
        length = c.get("length")
        if prefix is not None and length is not None:
            out["net_range"] = f"{prefix}/{length}"
    if "net_range" not in out:
        start, end = doc.get("startAddress"), doc.get("endAddress")
        if start and end:
            out["net_range"] = f"{start} - {end}"
        elif doc.get("handle"):
            out["net_range"] = str(doc["handle"])

    if doc.get("name"):
        out["net_name"] = doc["name"]
    if doc.get("country"):
        out["net_country"] = doc["country"]

    entities = doc.get("entities") or []
    # Org: registrant first, then administrative.
    for role in ("registrant", "administrative", "technical"):
        ents = _entities_by_role(entities, role)
        if ents:
            name = _entity_name(ents[0])
            if name:
                out["net_org"] = name
                break

    abuse = _entities_by_role(entities, "abuse")
    if abuse:
        email = _entity_email(abuse[0])
        if email:
            out["net_abuse_email"] = email

    return out


async def fetch_ip(client, ip: str, limiter: Optional[RateLimiter] = None,
                   base: str = RDAP_BASE) -> Dict[str, object]:
    """Return flat network-whois columns for ``ip`` (or ``{}``)."""
    if limiter is not None:
        await limiter.acquire()
    doc = await get_json(client, f"{base}/ip/{ip}")
    return parse_ip_rdap(doc)
