"""PeeringDB network adapter (offline).

PeeringDB publishes a free JSON dump of networks keyed by ASN
(``{"data": [{"asn", "name", "info_type", ...}]}``). We join it on the ASN
already resolved (by MaxMind/Brno) to fill the operator name and network type
(Content / NSP / Cable/DSL / Enterprise …).
"""

from __future__ import annotations

import json
from typing import Dict, Iterable


def _iter_nets(path: str) -> Iterable[dict]:
    """Yield network objects, streaming and tolerating a truncated dump."""
    import ijson
    with open(path, "rb") as fh:
        # PeeringDB dump is {"data": [ ... ]}; fall back to a bare array.
        head = fh.read(64).lstrip()
        fh.seek(0)
        prefix = "item" if head[:1] == b"[" else "data.item"
        items = ijson.items(fh, prefix)
        while True:
            try:
                yield next(items)
            except StopIteration:
                break
            except ijson.JSONError:
                break  # truncated/partial download -> use what we parsed


def parse_peeringdb(path: str) -> Dict[int, dict]:
    """Parse a PeeringDB ``net`` dump into ``{asn: {name, info_type}}``."""
    out: Dict[int, dict] = {}
    for net in _iter_nets(path):
        if not isinstance(net, dict):
            continue
        asn = net.get("asn")
        if asn is None:
            continue
        try:
            asn = int(asn)
        except (TypeError, ValueError):
            continue
        out[asn] = {
            "name": net.get("name") or "",
            "info_type": net.get("info_type") or "",
        }
    return out


def run_peeringdb(store, path: str, progress=None) -> int:
    """Fill asn_org/asn_type for domains whose ASN is in PeeringDB."""
    info = parse_peeringdb(path)
    matched = 0
    work = list(store.iter_asns(flag="s_peeringdb"))
    with store.batch():
        for domain, asn in work:
            data = info.get(asn)
            if data:
                store.update_asn_info(
                    domain,
                    asn_org=data["name"] or None,
                    asn_type=data["info_type"] or None,
                )
                matched += 1
                if progress is not None:
                    progress.update(1)
            store.mark_row_done(domain, "s_peeringdb")
    return matched
