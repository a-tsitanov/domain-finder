"""Flexible blocklist parser + threat-labelling stage.

Handles three shapes with one entry point:
  * hosts files   ``0.0.0.0 bad.domain``
  * CSV dumps     URLhaus / PhishTank / ThreatFox (domain/url column)
  * plain lists   one domain per line

It produces ``dict[bad_domain] -> set(list_names)`` and matches that against
the working set in the store, writing ``threat_label`` / ``threat_sources``.
The store's COALESCE writer guarantees a benign label from here never
downgrades a richer ``phishing`` / ``malware`` label set upstream.
"""

from __future__ import annotations

import csv
import ipaddress
import os
from typing import Dict, Iterable, List, Optional, Set

from ..normalize import normalize_domain

# Sentinel IPs that begin a hosts-file line.
_HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "255.255.255.255"}
# Header names (lower-cased) that hold a domain/url in known CSV dumps.
_URL_COLUMN_HINTS = ("url", "domain", "host", "hostname", "ioc", "ioc_value")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def domain_from_token(token: str) -> Optional[str]:
    """Normalize a single token to a bare domain, rejecting IP literals."""
    token = token.strip().strip('"').strip("'")
    if not token:
        return None
    d = normalize_domain(token)
    if d is None or _is_ip(d):
        return None
    return d


def _looks_like_hosts(sample: List[str]) -> bool:
    hits = 0
    for line in sample:
        parts = line.split()
        if parts and (parts[0] in _HOSTS_IPS or _is_ip(parts[0])):
            hits += 1
    return hits > 0 and hits >= len(sample) / 2


def _parse_hosts(lines: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        if parts[0] in _HOSTS_IPS or _is_ip(parts[0]):
            tokens = parts[1:]
        else:
            tokens = parts
        for tok in tokens:
            d = domain_from_token(tok)
            if d:
                out.add(d)
    return out


def _parse_csv(lines: List[str]) -> Set[str]:
    out: Set[str] = set()
    reader = csv.reader(lines)
    rows = [r for r in reader if r]
    if not rows:
        return out

    header = rows[0]
    header_lower = [c.strip().lower() for c in header]
    # Prefer columns whose header is exactly a hint (avoids picking up
    # reference columns like PhishTank's "phish_detail_url").
    idxs = [i for i, c in enumerate(header_lower) if c in _URL_COLUMN_HINTS]
    if not idxs:
        idxs = [i for i, c in enumerate(header_lower)
                if any(h in c for h in _URL_COLUMN_HINTS)]

    if idxs:
        data_rows = rows[1:]
        for row in data_rows:
            for i in idxs:
                if i < len(row):
                    d = domain_from_token(row[i])
                    if d:
                        out.add(d)
        return out

    # No recognizable header: prefer URL-looking cells, else first domain cell.
    for row in rows:
        url_cells = [c for c in row if "://" in c]
        if url_cells:
            for c in url_cells:
                d = domain_from_token(c)
                if d:
                    out.add(d)
        else:
            for c in row:
                d = domain_from_token(c)
                if d:
                    out.add(d)
                    break
    return out


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


def _is_header_comment(text: str) -> bool:
    """True if a (de-commented) line looks like a CSV header with a hint column."""
    if "," not in text:
        return False
    fields = [f.strip().strip('"').lower() for f in text.split(",")]
    return any(f in _URL_COLUMN_HINTS for f in fields)


def parse_blocklist(path: str) -> Set[str]:
    """Parse one blocklist file into a set of bad domains."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw_lines = fh.readlines()

    # Separate full-line comments (some feeds, e.g. URLhaus, hide the CSV
    # header inside the comment block) from the data body.
    header_candidate = None
    body = []
    for line in raw_lines:
        st = line.strip()
        if not st:
            continue
        if st.startswith("#"):
            decommented = st.lstrip("#").strip()
            if header_candidate is None and _is_header_comment(decommented):
                header_candidate = decommented
            continue
        body.append(st)

    if not body:
        return set()

    sample = body[:50]
    if _looks_like_hosts(sample):
        return _parse_hosts([_strip_comment(l) for l in body])

    if header_candidate is not None or any("," in l for l in sample):
        rows = [header_candidate] + body if header_candidate else body
        return _parse_csv(rows)

    # Plain list: one domain per line. Lines with spaces ("not a domain")
    # fail normalization and are dropped.
    out: Set[str] = set()
    for line in body:
        d = domain_from_token(_strip_comment(line))
        if d:
            out.add(d)
    return out


def _list_name(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


def label_for_list(name: str) -> str:
    """Infer a threat label from a blocklist's name."""
    n = name.lower()
    if "phish" in n or "openphish" in n:
        return "phishing"
    if any(k in n for k in ("urlhaus", "threatfox", "malware", "feodo",
                            "sslbl", "bazaar", "c2")):
        return "malware"
    return "blocklisted"


# Rank used to pick the strongest label when a domain hits several lists.
_LABEL_RANK = {"benign": 0, "blocklisted": 1, "phishing": 2, "malware": 3}


def build_bad_map(paths: Iterable[str]) -> Dict[str, Set[str]]:
    """Aggregate several blocklists into ``domain -> {list names}``."""
    bad: Dict[str, Set[str]] = {}
    for path in paths:
        name = _list_name(path)
        for domain in parse_blocklist(path):
            bad.setdefault(domain, set()).add(name)
    return bad


def run_blocklists(store, paths, batch_size: int = 5000, progress=None) -> int:
    """Match the working set against blocklists and write threat labels.

    Returns the number of domains that matched at least one list.
    """
    bad = build_bad_map(paths)
    if not bad:
        return 0

    matched = 0
    with store.batch():
        for row in store.iter_rows_pending("s_threat", batch_size):
            domain = row["domain"]
            lists = bad.get(domain)
            if lists:
                # Label is the strongest one implied by the matching lists; the
                # store's COALESCE keeps a richer upstream label if one exists.
                label = max((label_for_list(n) for n in lists),
                            key=lambda l: _LABEL_RANK.get(l, 0))
                store.update_threat(
                    domain,
                    threat_label=label,
                    threat_sources=",".join(sorted(lists)),
                )
                matched += 1
            store.mark_row_done(domain, "s_threat")
            if progress is not None:
                progress.update(1)
    return matched
