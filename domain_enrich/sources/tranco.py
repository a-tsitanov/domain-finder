"""Tranco popularity-rank adapter (offline).

The Tranco list (https://tranco-list.eu) is a ``rank,domain`` CSV. We load it
into a ``domain -> rank`` map and stamp the rank onto matching domains. A rank
is a cheap, powerful signal for separating legitimate sites from noise.
"""

from __future__ import annotations

import csv
from typing import Dict, Iterable

from ..normalize import normalize_domain


def parse_popularity(path: str) -> Dict[str, int]:
    """Parse any popularity list into ``{domain: rank}``, format-agnostic.

    Handles Tranco/Umbrella (``rank,domain``), Majestic
    (``GlobalRank,TldRank,Domain,…``) and DomCop (``Rank,Domain,…``) by
    picking, per row, the first integer field as rank and the first
    domain-looking field as the domain. Header rows (no integer) are skipped.
    """
    out: Dict[str, int] = {}
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.reader(fh):
            if not row:
                continue
            rank = None
            domain = None
            for cell in row:
                cell = cell.strip().strip('"')
                if rank is None and cell.isdigit():
                    rank = int(cell)
                elif domain is None:
                    d = normalize_domain(cell)
                    if d:
                        domain = d
            if rank is not None and domain is not None:
                cur = out.get(domain)
                if cur is None or rank < cur:
                    out[domain] = rank
    return out


def parse_tranco(path: str) -> Dict[str, int]:
    """Parse a Tranco ``rank,domain`` CSV into ``{domain: rank}``."""
    out: Dict[str, int] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or "," not in line:
                continue
            rank_s, _, domain_s = line.partition(",")
            try:
                rank = int(rank_s)
            except ValueError:
                continue  # header row ("rank,domain") or junk
            domain = normalize_domain(domain_s)
            if domain:
                out.setdefault(domain, rank)
    return out


def run_popularity(store, paths: Iterable[str], progress=None) -> int:
    """Stamp best (smallest) popularity rank across one or more lists."""
    ranks: Dict[str, int] = {}
    for path in paths:
        for domain, rank in parse_popularity(path).items():
            cur = ranks.get(domain)
            if cur is None or rank < cur:
                ranks[domain] = rank

    matched = 0
    with store.batch():
        for row in store.iter_rows_pending("s_tranco", 5000):
            domain = row["domain"]
            rank = ranks.get(domain)
            if rank is not None:
                store.update_tranco(domain, popularity_rank=rank)
                matched += 1
                if progress is not None:
                    progress.update(1)
            store.mark_row_done(domain, "s_tranco")
    return matched


def run_tranco(store, path: str, progress=None) -> int:
    """Backward-compatible single-file wrapper around run_popularity."""
    return run_popularity(store, [path], progress=progress)
