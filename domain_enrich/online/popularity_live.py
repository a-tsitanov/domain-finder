"""Live popularity rank via Cloudflare Radar (optional).

Needs a free Cloudflare API token; without one the stage is skipped. Returns the
domain's rank when Radar has it. Best-effort: Radar exposes ranking buckets
rather than a single global rank for every domain, so a miss is normal.
"""

from __future__ import annotations

from typing import Dict, Optional

from .http import get_json
from .ratelimit import RateLimiter

RADAR_BASE = "https://api.cloudflare.com/client/v4/radar/ranking/domain"


async def fetch_rank(client, domain: str, token: Optional[str] = None,
                     limiter: Optional[RateLimiter] = None) -> Dict[str, object]:
    if not token:
        return {}
    if limiter is not None:
        await limiter.acquire()
    data = await get_json(client, f"{RADAR_BASE}/{domain}",
                          headers={"Authorization": f"Bearer {token}"})
    if not isinstance(data, dict):
        return {}
    result = data.get("result") or {}
    details = result.get("details_0") or result.get("details") or {}
    rank = details.get("rank") if isinstance(details, dict) else None
    if rank is None:
        rank = result.get("rank")
    if isinstance(rank, int):
        return {"popularity_rank": rank}
    return {}
