"""Reverse-DNS (PTR) adapter — fully offline.

Reads a reverse-DNS dump (JSON-lines, gzip or plain) of records keyed by IP,
e.g. the Rapid7 Sonar RDNS format ``{"name": <ip>, "type": "ptr",
"value": <hostname>}``. Like the FDNS adapter, it only keeps records for IPs
that already exist in the working set, so memory stays bounded by matched IPs.
"""

from __future__ import annotations

import gzip
import json
from typing import Dict, Iterable, Set

# Record types accepted as a PTR. Many RDNS dumps omit the type field entirely.
_PTR_TYPES = ("ptr", "", None)


def accumulate_rdns(records: Iterable[dict], ipset: Set[str]) -> Dict[str, set]:
    """Group PTR hostnames per IP, restricted to IPs in ``ipset``."""
    acc: Dict[str, set] = {}
    for rec in records:
        ip = rec.get("name")
        value = rec.get("value")
        rtype = rec.get("type")
        if ip not in ipset or not value:
            continue
        if rtype is not None and str(rtype).lower() not in ("ptr", ""):
            continue
        acc.setdefault(ip, set()).add(value)
    return acc


def _open(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _iter_json(path: str):
    with _open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def run_rdns(store, path: str, progress=None) -> int:
    """Fill the ``ptr`` column for domains whose IPs appear in the RDNS dump."""
    pending = list(store.iter_ips(flag="s_rdns"))
    ipset: Set[str] = set()
    for _domain, ips in pending:
        ipset.update(ips)

    ptr_map = accumulate_rdns(_iter_json(path), ipset)

    matched = 0
    with store.batch():
        for domain, ips in pending:
            names = sorted({n for ip in ips for n in ptr_map.get(ip, ())})
            if names:
                store.update_dns(domain, ptr=names)
                matched += 1
                if progress is not None:
                    progress.update(1)
            store.mark_row_done(domain, "s_rdns")
    return matched
