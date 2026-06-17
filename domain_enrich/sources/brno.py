"""Brno BUT dataset (Zenodo 14332167) adapter.

The dataset ships as a handful of large MongoDB Extended JSON files, each a
top-level array of documents. We stream them with ``ijson`` (one pass, no full
load), unwrap Extended-JSON scalars, and lift DNS / TLS / RDAP / IP data plus a
threat label derived from the file name. Only documents whose domain is in the
working set are written.
"""

from __future__ import annotations

import glob
import json
import os
from decimal import Decimal
from typing import Dict, Iterable, List, Optional

from ..normalize import normalize_domain

# Common keys that hold the useful scalar inside a DNS record dict.
_VALUE_KEYS = ("value", "data", "ip", "address", "target", "exchange", "ns", "name")


def unwrap_ejson(value):
    """Recursively convert MongoDB Extended JSON into plain Python values."""
    if isinstance(value, dict):
        if len(value) == 1:
            (k, v), = value.items()
            if k == "$numberInt" or k == "$numberLong":
                return int(v)
            if k == "$numberDouble" or k == "$numberDecimal":
                return float(v)
            if k == "$oid":
                return v
            if k == "$date":
                return unwrap_ejson(v)
        return {k: unwrap_ejson(v) for k, v in value.items()}
    if isinstance(value, list):
        return [unwrap_ejson(v) for v in value]
    if isinstance(value, Decimal):
        # ijson emits Decimal for every JSON number; make it JSON-serializable.
        return int(value) if value == value.to_integral_value() else float(value)
    return value


def label_from_filename(name: str) -> Optional[str]:
    """Map a Brno file name to a threat label, or None if unrecognized."""
    base = os.path.basename(name).lower()
    if base.startswith("benign"):  # benign_umbrella / benign_cesnet
        return "benign"
    if "phishing" in base:
        return "phishing"
    if "malware" in base:
        return "malware"
    return None


def collect_files(paths: Iterable[str]) -> List[str]:
    """Expand globs/dirs into a flat list of files, excluding schema.json."""
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            candidates = sorted(glob.glob(os.path.join(p, "*")))
        else:
            candidates = sorted(glob.glob(p)) or ([p] if os.path.exists(p) else [])
        for c in candidates:
            if not os.path.isfile(c):
                continue
            if os.path.basename(c) == "schema.json":
                continue
            out.append(c)
    return out


def _extract_values(records) -> List[str]:
    """Pull scalar string values out of a DNS record list."""
    out: List[str] = []
    if records is None:
        return out
    if not isinstance(records, list):
        records = [records]
    for rec in records:
        rec = unwrap_ejson(rec)
        if isinstance(rec, str):
            out.append(rec)
        elif isinstance(rec, dict):
            for key in _VALUE_KEYS:
                if key in rec and isinstance(rec[key], str):
                    out.append(rec[key])
                    break
    return out


def _get_ci(d: dict, *names) -> Optional[object]:
    """Case-insensitive dict lookup over several candidate names."""
    lower = {k.lower(): v for k, v in d.items()}
    for n in names:
        if n.lower() in lower:
            return lower[n.lower()]
    return None


def lift_record(doc: dict, label: Optional[str] = None) -> Optional[dict]:
    """Lift the fields we care about out of one Brno document.

    Returns ``None`` if the document has no usable domain. The domain is
    normalized so it joins against the working set.
    """
    doc = unwrap_ejson(doc)
    raw_domain = (
        doc.get("domain_name")
        or doc.get("name")
        or doc.get("domain")
    )
    if not raw_domain:
        return None
    domain = normalize_domain(raw_domain)
    if domain is None:
        return None

    dns = doc.get("dns") or {}
    is_dns = isinstance(dns, dict)
    a = _extract_values(_get_ci(dns, "A")) if is_dns else []
    aaaa = _extract_values(_get_ci(dns, "AAAA")) if is_dns else []
    ns = _extract_values(_get_ci(dns, "NS")) if is_dns else []
    mx = _extract_values(_get_ci(dns, "MX")) if is_dns else []
    txt = _extract_values(_get_ci(dns, "TXT")) if is_dns else []
    cname = _extract_values(_get_ci(dns, "CNAME")) if is_dns else []
    soa = _get_ci(dns, "SOA") if is_dns else None
    if soa is not None:
        soa = json.dumps(unwrap_ejson(soa), ensure_ascii=False, sort_keys=True)

    # Unique IPs from A + AAAA, plus any addresses present in ip_data; lift PTR
    # (reverse DNS) too if the ip_data carries it.
    ip_data = doc.get("ip_data")
    ips = list(dict.fromkeys(a + aaaa))
    ptr: List[str] = []
    if isinstance(ip_data, list):
        for entry in ip_data:
            if isinstance(entry, dict):
                ip = entry.get("ip") or entry.get("address")
                if isinstance(ip, str) and ip not in ips:
                    ips.append(ip)
                rev = entry.get("ptr") or entry.get("rdns") or entry.get("reverse_dns")
                if isinstance(rev, str):
                    ptr.append(rev)
                elif isinstance(rev, list):
                    ptr.extend(x for x in rev if isinstance(x, str))
    ptr = list(dict.fromkeys(ptr))

    return {
        "domain": domain,
        "a": a or None,
        "aaaa": aaaa or None,
        "ns": ns or None,
        "mx": mx or None,
        "ips": ips or None,
        "txt": txt or None,
        "cname": cname or None,
        "ptr": ptr or None,
        "soa": soa,
        "tls": doc.get("tls") or None,
        "rdap": doc.get("rdap") or None,
        "ip_data": ip_data or None,
        "threat_label": label,
    }


def run_brno(store, paths, batch_size: int = 2000, progress=None) -> int:
    """Stream the Brno files and write enrichment for matching domains.

    Returns the number of domains matched. Imported lazily so the module loads
    even when ``ijson`` is absent.
    """
    import ijson

    from . import rdap as rdap_mod

    work = store.all_domains()
    files = collect_files(paths)
    matched = 0

    for path in files:
        label = label_from_filename(path)
        with open(path, "rb") as fh, store.batch():
            items = ijson.items(fh, "item")
            while True:
                # Tolerate a truncated/corrupt dump (e.g. a partial download):
                # process everything parsed so far, then stop on the bad tail.
                try:
                    doc = next(items)
                except StopIteration:
                    break
                except ijson.JSONError as exc:
                    if progress is None:
                        print(f"WARNING: brno: stopped early on {path}: {exc}",
                              file=__import__("sys").stderr)
                    break
                rec = lift_record(doc, label)
                if rec is None or rec["domain"] not in work:
                    continue
                store.update_dns(
                    rec["domain"],
                    a=rec["a"], aaaa=rec["aaaa"], ns=rec["ns"], mx=rec["mx"],
                    ips=rec["ips"], tls=rec["tls"], rdap=rec["rdap"],
                    ip_data=rec["ip_data"], txt=rec["txt"], soa=rec["soa"],
                    cname=rec["cname"], ptr=rec["ptr"],
                )
                # Brno already carries an RDAP object -> lift it into the flat
                # domain-whois columns, fully offline.
                if rec["rdap"]:
                    whois = rdap_mod.parse_rdap(rec["rdap"])
                    if whois:
                        store.update_rdap(rec["domain"], **whois)
                if rec["threat_label"]:
                    store.update_threat(rec["domain"], threat_label=rec["threat_label"])
                matched += 1
                if progress is not None:
                    progress.update(1)

    # Mark every domain's brno flag done (matched or not) so the stage resumes.
    with store.batch() as conn:
        conn.execute("UPDATE domains SET s_brno = 1 WHERE s_brno = 0")
    return matched
