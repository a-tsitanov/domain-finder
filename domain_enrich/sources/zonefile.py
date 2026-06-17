"""DNS zone-file adapter (offline) — e.g. ICANN CZDS gTLD zones.

Parses flat master-format zone files (one record per line, fully-qualified
names with trailing dots, as CZDS publishes) and fills NS / A / AAAA for
matching domains. This is the offline "forward DNS" layer: who is delegated and
the glue/address records straight from the zone.

Note: deliberately simple — it does not interpret $ORIGIN / $TTL directives or
multi-line parenthesised records (CZDS zones are flat). Supports gzip.
"""

from __future__ import annotations

import glob
import gzip
import os
from typing import Dict, List

from ..normalize import normalize_domain

_WANTED = {"NS": "ns", "A": "a", "AAAA": "aaaa"}


def _open(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _collect(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            out.extend(sorted(glob.glob(os.path.join(p, "*"))))
        else:
            out.extend(sorted(glob.glob(p)) or ([p] if os.path.exists(p) else []))
    return [f for f in out if os.path.isfile(f)]


def _add(recs: Dict[str, dict], name: str, key: str, value: str) -> None:
    slot = recs.setdefault(name, {"ns": [], "a": [], "aaaa": []})
    if value not in slot[key]:
        slot[key].append(value)


def parse_zone(path: str) -> Dict[str, dict]:
    """Parse a flat zone file into ``{domain: {ns, a, aaaa}}``."""
    recs: Dict[str, dict] = {}
    with _open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] in ";$":
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            # name [TTL] [CLASS] TYPE rdata...
            owner = parts[0]
            rtype = None
            rdata = None
            for i in range(1, len(parts)):
                tok = parts[i].upper()
                if tok in _WANTED:
                    rtype = tok
                    rdata = parts[i + 1] if i + 1 < len(parts) else None
                    break
            if not rtype or not rdata:
                continue
            domain = normalize_domain(owner.rstrip("."))
            if domain is None:
                continue
            value = rdata.rstrip(".") if rtype == "NS" else rdata
            _add(recs, domain, _WANTED[rtype], value)
    return recs


def run_zone(store, paths, progress=None) -> int:
    """Fill NS/A/AAAA for matching domains from offline zone files."""
    work = store.all_domains()
    matched = 0
    seen = set()
    with store.batch():
        for path in _collect(list(paths)):
            for domain, rec in parse_zone(path).items():
                if domain not in work or domain in seen:
                    continue
                a = rec["a"] or None
                aaaa = rec["aaaa"] or None
                ips = list(dict.fromkeys((a or []) + (aaaa or []))) or None
                store.update_dns(domain, ns=rec["ns"] or None, a=a, aaaa=aaaa, ips=ips)
                seen.add(domain)
                matched += 1
                if progress is not None:
                    progress.update(1)
        store.conn.execute("UPDATE domains SET s_zone = 1 WHERE s_zone = 0")
    return matched
