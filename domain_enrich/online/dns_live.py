"""Live DNS resolution (async).

Replaces the offline DNS sources (Brno / Rapid7 FDNS / zone files / rdns dump)
with real queries via dnspython's async resolver. Resolves A, AAAA, NS, MX,
TXT, CNAME, SOA for the domain and reverse PTR for each resolved IP, returning
the same flat columns the offline DNS writers fill.

The resolver is injectable so tests can supply a fake without touching the
network.
"""

from __future__ import annotations

from typing import Dict, List, Optional

_RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA")


def _default_resolver(timeout: float, lifetime: float):
    import dns.asyncresolver
    r = dns.asyncresolver.Resolver()
    r.timeout = timeout
    r.lifetime = lifetime
    return r


def _rdata_to_str(rdtype: str, rdata) -> Optional[str]:
    try:
        if rdtype == "MX":
            return str(rdata.exchange).rstrip(".").lower()
        if rdtype in ("NS", "CNAME"):
            return str(rdata.target).rstrip(".").lower()
        if rdtype == "PTR":
            target = getattr(rdata, "target", rdata)
            return str(target).rstrip(".").lower()
        if rdtype == "SOA":
            return str(rdata.mname).rstrip(".").lower()
        if rdtype == "TXT":
            parts = getattr(rdata, "strings", None)
            if parts is not None:
                return "".join(
                    p.decode("utf-8", "replace") if isinstance(p, bytes) else str(p)
                    for p in parts
                )
        return str(rdata)
    except Exception:
        return None


async def _query(resolver, name: str, rdtype: str) -> List[str]:
    """Resolve one record type, swallowing the expected "no data" errors."""
    try:
        answer = await resolver.resolve(name, rdtype)
    except Exception:
        # NXDOMAIN / NoAnswer / Timeout / NoNameservers -> just no records.
        return []
    out: List[str] = []
    for rdata in answer:
        s = _rdata_to_str(rdtype, rdata)
        if s:
            out.append(s)
    return out


async def resolve(domain: str, resolver=None, timeout: float = 5.0,
                  lifetime: float = 10.0, do_ptr: bool = True) -> Dict[str, object]:
    """Resolve ``domain`` and return DNS columns for ``store.update_dns``.

    Returns a dict with any of: a, aaaa, ns, mx, txt, cname, soa, ptr, ips.
    Empty record sets are omitted. ``soa`` is a scalar (first value); the rest
    are lists.
    """
    resolver = resolver or _default_resolver(timeout, lifetime)
    out: Dict[str, object] = {}

    for rdtype in _RECORD_TYPES:
        values = await _query(resolver, domain, rdtype)
        if not values:
            continue
        key = rdtype.lower()
        if rdtype == "SOA":
            out["soa"] = values[0]
        else:
            out[key] = values

    ips: List[str] = []
    ips.extend(out.get("a", []) or [])
    ips.extend(out.get("aaaa", []) or [])
    # de-dup, preserve order
    ips = list(dict.fromkeys(ips))
    if ips:
        out["ips"] = ips

    if do_ptr and ips:
        ptrs: List[str] = []
        import dns.reversename
        for ip in ips:
            try:
                rev = dns.reversename.from_address(ip)
            except Exception:
                continue
            names = await _query(resolver, rev.to_text(), "PTR")
            ptrs.extend(names)
        ptrs = list(dict.fromkeys(ptrs))
        if ptrs:
            out["ptr"] = ptrs

    return out
