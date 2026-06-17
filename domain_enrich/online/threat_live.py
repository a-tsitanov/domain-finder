"""Live threat lookup via abuse.ch community APIs.

* **URLhaus** host API — is the domain known for malware distribution?
* **ThreatFox** — is the domain a known IOC?

Both need a free Auth-Key (https://auth.abuse.ch/); without one this stage is
skipped. Optionally, a preloaded :class:`domain_enrich.sources.ipthreat.IpThreat`
matcher (Feodo/SSLBL/Spamhaus feeds) flags domains by resolved IP — reusing the
offline matcher.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..sources.blocklists import _LABEL_RANK, label_for_list
from .ratelimit import RateLimiter

URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"


async def _post_json(client, url: str, *, data=None, json=None, headers=None,
                     limiter: Optional[RateLimiter] = None):
    if limiter is not None:
        await limiter.acquire()
    try:
        resp = await client.post(url, data=data, json=json, headers=headers)
        if resp.status_code >= 400:
            return None
        return resp.json()
    except Exception:
        return None


async def check(client, domain: str, ips: Optional[List[str]] = None,
                auth_key: Optional[str] = None, limiter: Optional[RateLimiter] = None,
                ip_matcher=None) -> Dict[str, object]:
    """Return threat columns for ``domain`` (or ``{}``).

    Combines URLhaus + ThreatFox (domain-keyed, needs ``auth_key``) with an
    optional IP/CIDR matcher. The strongest label wins.
    """
    labels: List[str] = []
    sources: List[str] = []

    if auth_key:
        headers = {"Auth-Key": auth_key}
        uh = await _post_json(client, URLHAUS_HOST, data={"host": domain},
                              headers=headers, limiter=limiter)
        if isinstance(uh, dict) and uh.get("query_status") == "ok" and uh.get("urls"):
            labels.append("malware")
            sources.append("urlhaus")

        tf = await _post_json(client, THREATFOX,
                              json={"query": "search_ioc", "search_term": domain},
                              headers=headers, limiter=limiter)
        if isinstance(tf, dict) and tf.get("query_status") == "ok" and tf.get("data"):
            labels.append("malware")
            sources.append("threatfox")

    if ip_matcher is not None and ips:
        names = set()
        for ip in ips:
            names |= ip_matcher.match(ip)
        if names:
            labels.append(max((label_for_list(n) for n in names),
                              key=lambda l: _LABEL_RANK.get(l, 0)))
            sources.extend(sorted(names))

    if not labels:
        return {}
    label = max(labels, key=lambda l: _LABEL_RANK.get(l, 0))
    return {"threat_label": label,
            "threat_sources": ",".join(dict.fromkeys(sources))}
