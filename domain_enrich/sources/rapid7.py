"""Rapid7 Open Data / Project Sonar FDNS adapter.

The FDNS dump is a huge gzip'd JSON-lines file of
``{"name", "type", "value"}`` records. We stream it line by line and keep an
accumulator only for names present in the working set (<= 2M entries), so the
memory footprint stays bounded by the number of matched domains, not the dump.
"""

from __future__ import annotations

import gzip
import json
from typing import Dict, Iterable, Set

_DNS_TYPES = ("a", "aaaa")


def accumulate_fdns(records: Iterable[dict], work: Set[str]) -> Dict[str, dict]:
    """Accumulate A/AAAA values per matched domain from FDNS records."""
    acc: Dict[str, dict] = {}
    for rec in records:
        name = rec.get("name")
        rtype = rec.get("type")
        value = rec.get("value")
        if name not in work or rtype not in _DNS_TYPES or not value:
            continue
        slot = acc.setdefault(name, {"a": set(), "aaaa": set()})
        slot[rtype].add(value)
    return acc


def _iter_gzip_json(path: str):
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def run_rapid7(store, path: str, flush_every: int = 50000, progress=None) -> int:
    """Stream the FDNS dump and fill empty A/AAAA/ips for matched domains.

    Returns the number of domains matched. The store's COALESCE writer means
    Brno-provided DNS is never overwritten; only empty fields are filled.
    """
    work = store.all_domains()
    acc = accumulate_fdns(_iter_gzip_json(path), work)

    matched = 0
    with store.batch():
        for domain, slot in acc.items():
            a = sorted(slot["a"])
            aaaa = sorted(slot["aaaa"])
            ips = list(dict.fromkeys(a + aaaa))
            store.update_dns(
                domain,
                a=a or None,
                aaaa=aaaa or None,
                ips=ips or None,
            )
            matched += 1
            if progress is not None:
                progress.update(1)
        # Mark stage done for all rows so re-runs skip them.
        store.conn.execute("UPDATE domains SET s_rapid7 = 1 WHERE s_rapid7 = 0")
    return matched
