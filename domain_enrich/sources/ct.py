"""Certificate Transparency adapter (offline dump).

Consumes a CT dump (JSON-lines or JSON array of cert records, e.g. a crt.sh
export) and fills Subject Alternative Names (and TLS cipher/protocol if present)
for matching domains. Useful for domains the Brno dataset did not cover.

No network: you supply a pre-exported CT dump; this only joins against it.
"""

from __future__ import annotations

import glob
import json
import os
from typing import List, Optional, Tuple

from ..normalize import normalize_domain


def _collect(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            out.extend(sorted(glob.glob(os.path.join(p, "*"))))
        else:
            out.extend(sorted(glob.glob(p)) or ([p] if os.path.exists(p) else []))
    return [f for f in out if os.path.isfile(f)]


def _iter_objects(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(64).lstrip()
        fh.seek(0)
        if head[:1] == "[":
            try:
                yield from json.load(fh)
            except json.JSONDecodeError:
                return
        else:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue


def parse_ct_record(rec: dict) -> Tuple[Optional[str], List[str]]:
    """Return (primary_domain, [SANs]) from one CT record."""
    primary = rec.get("common_name") or rec.get("ldhName") or rec.get("domain")
    primary = normalize_domain(primary) if primary else None

    raw_sans: List[str] = []
    nv = rec.get("name_value")
    if isinstance(nv, str):
        raw_sans.extend(nv.replace(",", "\n").splitlines())
    for key in ("sans", "san", "dns_names", "subject_alt_names"):
        val = rec.get(key)
        if isinstance(val, list):
            raw_sans.extend(str(x) for x in val)

    sans = []
    for s in raw_sans:
        d = normalize_domain(s.lstrip("*.")) if s else None
        if d and d not in sans:
            sans.append(d)
    return primary, sans


def run_ct(store, paths, progress=None) -> int:
    """Fill SANs (and TLS) for domains found in an offline CT dump."""
    work = store.all_domains()
    matched = 0
    seen = set()
    with store.batch():
        for path in _collect(list(paths)):
            for rec in _iter_objects(path):
                if not isinstance(rec, dict):
                    continue
                primary, sans = parse_ct_record(rec)
                # Attribute the cert to whichever covered name is in the work set.
                targets = {d for d in ([primary] + sans) if d in work}
                tls = None
                if rec.get("cipher") or rec.get("protocol"):
                    tls = {"cipher": rec.get("cipher"), "protocol": rec.get("protocol")}
                for domain in targets:
                    if domain in seen:
                        continue
                    store.update_san(domain, san=sans or None, tls=tls)
                    seen.add(domain)
                    matched += 1
                    if progress is not None:
                        progress.update(1)
        store.conn.execute("UPDATE domains SET s_ct = 1 WHERE s_ct = 0")
    return matched
