"""Stage orchestration: normalize -> brno -> rapid7 -> geo -> threat -> export.

Resumability works on two levels:
  * coarse  -- ``meta(stage, status)``; a stage marked ``done`` is skipped
              unless forced.
  * fine    -- per-row flags (``s_brno`` / ``s_rapid7`` / ``s_geo`` /
              ``s_threat``); a re-run only touches rows not yet marked.

Every source is optional: if its path argument is empty the stage is skipped
with a warning instead of failing.
"""

from __future__ import annotations

import sys
from typing import Iterable, List, Optional, Sequence, Set

from . import export as export_mod
from .normalize import read_input
from .store import Store

STAGE_FLAGS = {
    "brno": "s_brno",
    "rapid7": "s_rapid7",
    "geo": "s_geo",
    "threat": "s_threat",
    "tranco": "s_tranco",
    "netwhois": "s_netwhois",
    "rdns": "s_rdns",
    "rdap": "s_rdap",
    "ipthreat": "s_ipthreat",
    "peeringdb": "s_peeringdb",
    "ct": "s_ct",
    "zone": "s_zone",
}


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _warn(msg: str) -> None:
    print(f"WARNING: {msg}", file=sys.stderr, flush=True)


def _progress(total: Optional[int], desc: str):
    """Return a tqdm bar if available, else a no-op stand-in."""
    try:
        from tqdm import tqdm
        return tqdm(total=total, desc=desc, unit="dom")
    except Exception:  # tqdm missing -> silent no-op
        class _Null:
            def update(self, *a):
                pass

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass
        return _Null()


def _expand(paths) -> List[str]:
    """Expand directory entries to their files; drop paths that don't exist."""
    import glob
    import os
    out: List[str] = []
    for p in paths or ():
        if p and os.path.isdir(p):
            out.extend(sorted(f for f in glob.glob(os.path.join(p, "*"))
                              if os.path.isfile(f)))
        elif p and os.path.exists(p):
            out.append(p)
    return out


def _present(path: Optional[str]) -> Optional[str]:
    """Return ``path`` if it exists, else None (missing source -> skip)."""
    import os
    return path if path and os.path.exists(path) else None


def _maybe_reset(store: Store, stage: str, force: Set[str]) -> bool:
    """If forced, clear the stage. Returns True if the stage should run."""
    if stage in force:
        flag = STAGE_FLAGS.get(stage)
        if flag:
            store.reset_flag(flag)
        store.mark_stage(stage, "pending")
        return True
    if store.stage_done(stage):
        _log(f"[{stage}] already done, skipping (use --force {stage} to rerun)")
        return False
    return True


# -- stages --------------------------------------------------------------
def stage_normalize(store: Store, input_path: str, batch: int = 10000) -> int:
    store.mark_stage("normalize", "running")
    total_new = 0
    buf = []
    bar = _progress(None, "normalize")
    for normalized, original in read_input(input_path):
        buf.append((normalized, original))
        if len(buf) >= batch:
            total_new += store.add_domains(buf)
            bar.update(len(buf))
            buf = []
    if buf:
        total_new += store.add_domains(buf)
        bar.update(len(buf))
    bar.close()
    store.mark_stage("normalize", "done")
    _log(f"[normalize] {total_new} new domains; {len(store.all_domains())} total")
    return total_new


def stage_brno(store: Store, paths: Optional[Sequence[str]], force: Set[str]) -> int:
    if not paths:
        _warn("brno: no --brno-dir provided, skipping")
        return 0
    if not _maybe_reset(store, "brno", force):
        return 0
    from .sources import brno
    store.mark_stage("brno", "running")
    bar = _progress(None, "brno")
    matched = brno.run_brno(store, list(paths), progress=bar)
    bar.close()
    store.mark_stage("brno", "done")
    _log(f"[brno] matched {matched} domains")
    return matched


def stage_rapid7(store: Store, fdns: Optional[str], force: Set[str]) -> int:
    fdns = _present(fdns)
    if not fdns:
        _warn("rapid7: no --rapid7-fdns provided, skipping")
        return 0
    if not _maybe_reset(store, "rapid7", force):
        return 0
    from .sources import rapid7
    store.mark_stage("rapid7", "running")
    bar = _progress(None, "rapid7")
    matched = rapid7.run_rapid7(store, fdns, progress=bar)
    bar.close()
    store.mark_stage("rapid7", "done")
    _log(f"[rapid7] matched {matched} domains")
    return matched


def stage_geo(store: Store, city: Optional[str], asn: Optional[str],
              force: Set[str]) -> int:
    city, asn = _present(city), _present(asn)
    if not city and not asn:
        _warn("geo: no --maxmind-city/--maxmind-asn provided, skipping")
        return 0
    if not _maybe_reset(store, "geo", force):
        return 0
    from .sources import maxmind
    store.mark_stage("geo", "running")
    bar = _progress(None, "geo")
    enriched = maxmind.run_maxmind(store, city, asn, progress=bar)
    bar.close()
    store.mark_stage("geo", "done")
    _log(f"[geo] enriched {enriched} domains")
    return enriched


def stage_threat(store: Store, blocklists: Optional[Sequence[str]],
                 force: Set[str]) -> int:
    if not blocklists:
        _warn("threat: no --blocklist provided, skipping")
        return 0
    if not _maybe_reset(store, "threat", force):
        return 0
    from .sources import blocklists as bl
    blocklists = _expand(blocklists)
    if not blocklists:
        _warn("threat: no blocklist files found, skipping")
        return 0
    store.mark_stage("threat", "running")
    bar = _progress(None, "threat")
    matched = bl.run_blocklists(store, list(blocklists), progress=bar)
    bar.close()
    store.mark_stage("threat", "done")
    _log(f"[threat] matched {matched} domains")
    return matched


def stage_tranco(store: Store, path, force: Set[str]) -> int:
    # `path` may be a single file, a directory, or a list -> popularity ensemble.
    paths = _expand(path if isinstance(path, (list, tuple)) else [path])
    if not paths:
        _warn("tranco: no --tranco provided, skipping")
        return 0
    if not _maybe_reset(store, "tranco", force):
        return 0
    from .sources import tranco
    store.mark_stage("tranco", "running")
    bar = _progress(None, "tranco")
    matched = tranco.run_popularity(store, paths, progress=bar)
    bar.close()
    store.mark_stage("tranco", "done")
    _log(f"[tranco] ranked {matched} domains")
    return matched


def stage_ipthreat(store: Store, paths, force: Set[str]) -> int:
    paths = _expand(paths)
    if not paths:
        _warn("ipthreat: no --ipthreat provided, skipping")
        return 0
    if not _maybe_reset(store, "ipthreat", force):
        return 0
    from .sources import ipthreat
    store.mark_stage("ipthreat", "running")
    bar = _progress(None, "ipthreat")
    matched = ipthreat.run_ipthreat(store, paths, progress=bar)
    bar.close()
    store.mark_stage("ipthreat", "done")
    _log(f"[ipthreat] matched {matched} domains")
    return matched


def stage_peeringdb(store: Store, path: Optional[str], force: Set[str]) -> int:
    path = _present(path)
    if not path:
        _warn("peeringdb: no --peeringdb provided, skipping")
        return 0
    if not _maybe_reset(store, "peeringdb", force):
        return 0
    from .sources import peeringdb
    store.mark_stage("peeringdb", "running")
    bar = _progress(None, "peeringdb")
    matched = peeringdb.run_peeringdb(store, path, progress=bar)
    bar.close()
    store.mark_stage("peeringdb", "done")
    _log(f"[peeringdb] enriched {matched} domains")
    return matched


def stage_ct(store: Store, paths, force: Set[str]) -> int:
    paths = _expand(paths)
    if not paths:
        _warn("ct: no --ct-dump provided, skipping")
        return 0
    if not _maybe_reset(store, "ct", force):
        return 0
    from .sources import ct
    store.mark_stage("ct", "running")
    bar = _progress(None, "ct")
    matched = ct.run_ct(store, paths, progress=bar)
    bar.close()
    store.mark_stage("ct", "done")
    _log(f"[ct] matched {matched} domains")
    return matched


def stage_zone(store: Store, paths, force: Set[str]) -> int:
    paths = _expand(paths)
    if not paths:
        _warn("zone: no --zone provided, skipping")
        return 0
    if not _maybe_reset(store, "zone", force):
        return 0
    from .sources import zonefile
    store.mark_stage("zone", "running")
    bar = _progress(None, "zone")
    matched = zonefile.run_zone(store, paths, progress=bar)
    bar.close()
    store.mark_stage("zone", "done")
    _log(f"[zone] matched {matched} domains")
    return matched


def stage_netwhois(store: Store, rir_dump: Optional[Sequence[str]],
                   force: Set[str]) -> int:
    if not rir_dump:
        _warn("netwhois: no --rir-dump provided, skipping")
        return 0
    if not _maybe_reset(store, "netwhois", force):
        return 0
    from .sources import rir
    rir_dump = _expand(rir_dump)
    if not rir_dump:
        _warn("netwhois: no RIR dump files found, skipping")
        return 0
    store.mark_stage("netwhois", "running")
    bar = _progress(None, "netwhois")
    matched = rir.run_rir(store, list(rir_dump), progress=bar)
    bar.close()
    store.mark_stage("netwhois", "done")
    _log(f"[netwhois] matched {matched} domains")
    return matched


def stage_rdns(store: Store, rdns_dump: Optional[str], force: Set[str]) -> int:
    rdns_dump = _present(rdns_dump)
    if not rdns_dump:
        _warn("rdns: no --rdns-dump provided, skipping (PTR also comes from Brno ip_data)")
        return 0
    if not _maybe_reset(store, "rdns", force):
        return 0
    from .sources import rdns
    store.mark_stage("rdns", "running")
    bar = _progress(None, "rdns")
    matched = rdns.run_rdns(store, rdns_dump, progress=bar)
    bar.close()
    store.mark_stage("rdns", "done")
    _log(f"[rdns] matched {matched} domains")
    return matched


def stage_rdap(store: Store, rdap_dump: Optional[Sequence[str]],
               force: Set[str]) -> int:
    if not rdap_dump:
        _warn("rdap: no --rdap-dump provided, skipping (Brno already fills RDAP inline)")
        return 0
    if not _maybe_reset(store, "rdap", force):
        return 0
    from .sources import rdap
    rdap_dump = _expand(rdap_dump)
    if not rdap_dump:
        _warn("rdap: no RDAP dump files found, skipping")
        return 0
    store.mark_stage("rdap", "running")
    bar = _progress(None, "rdap")
    matched = rdap.run_rdap(store, list(rdap_dump), progress=bar)
    bar.close()
    store.mark_stage("rdap", "done")
    _log(f"[rdap] matched {matched} domains")
    return matched


def stage_export(store: Store, output: str, fields: Optional[List[str]],
                 fmt: str) -> dict:
    store.mark_stage("export", "running")
    results = export_mod.export(store, output, fields=fields, fmt=fmt)
    store.mark_stage("export", "done")
    for f, n in results.items():
        _log(f"[export] wrote {n} rows ({f}) -> {output}")
    return results


# -- single-domain lookup (interactive "dossier") ------------------------
def lookup_domain(
    domain: str,
    brno_dir: Optional[Sequence[str]] = None,
    rapid7_fdns: Optional[str] = None,
    maxmind_city: Optional[str] = None,
    maxmind_asn: Optional[str] = None,
    rir_dump: Optional[Sequence[str]] = None,
    rdns_dump: Optional[str] = None,
    blocklist: Optional[Sequence[str]] = None,
    tranco: Optional[str] = None,
    rdap_dump: Optional[Sequence[str]] = None,
    zone: Optional[Sequence[str]] = None,
    ipthreat: Optional[Sequence[str]] = None,
    peeringdb: Optional[str] = None,
    ct_dump: Optional[Sequence[str]] = None,
) -> Optional[dict]:
    """Enrich a single domain against the given sources and return a flat row.

    Uses an in-memory store, so it leaves no files behind — ideal for ad-hoc
    "write a query like a CLI" lookups inside the runner container.
    """
    from .normalize import normalize_domain
    from .export import flatten_row

    norm = normalize_domain(domain)
    if not norm:
        raise ValueError(f"not a valid domain: {domain!r}")

    # Honor "missing source -> skip": keep only paths that actually exist.
    brno_dir = _expand(brno_dir)
    rir_dump = _expand(rir_dump)
    blocklist = _expand(blocklist)
    rdap_dump = _expand(rdap_dump)
    zone = _expand(zone)
    ipthreat = _expand(ipthreat)
    ct_dump = _expand(ct_dump)
    tranco = _expand(tranco if isinstance(tranco, (list, tuple)) else [tranco])
    rapid7_fdns = _present(rapid7_fdns)
    rdns_dump = _present(rdns_dump)
    peeringdb = _present(peeringdb)
    maxmind_city, maxmind_asn = _present(maxmind_city), _present(maxmind_asn)

    store = Store(":memory:")
    try:
        store.add_domains([(norm, domain)])
        if brno_dir:
            from .sources import brno
            brno.run_brno(store, brno_dir)
        if rapid7_fdns:
            from .sources import rapid7
            rapid7.run_rapid7(store, rapid7_fdns)
        if zone:
            from .sources import zonefile
            zonefile.run_zone(store, zone)
        if maxmind_city or maxmind_asn:
            from .sources import maxmind
            maxmind.run_maxmind(store, maxmind_city, maxmind_asn)
        if rir_dump:
            from .sources import rir
            rir.run_rir(store, rir_dump)
        if peeringdb:
            from .sources import peeringdb as peeringdb_mod
            peeringdb_mod.run_peeringdb(store, peeringdb)
        if rdns_dump:
            from .sources import rdns
            rdns.run_rdns(store, rdns_dump)
        if blocklist:
            from .sources import blocklists
            blocklists.run_blocklists(store, blocklist)
        if ipthreat:
            from .sources import ipthreat as ipthreat_mod
            ipthreat_mod.run_ipthreat(store, ipthreat)
        if tranco:
            from .sources import tranco as tranco_mod
            tranco_mod.run_popularity(store, tranco)
        if ct_dump:
            from .sources import ct
            ct.run_ct(store, ct_dump)
        if rdap_dump:
            from .sources import rdap
            rdap.run_rdap(store, rdap_dump)

        row = next(iter(store.iter_rows(1)), None)
        return flatten_row(row) if row else None
    finally:
        store.close()


# -- full run ------------------------------------------------------------
def run(
    input_path: str,
    db: str,
    output: str,
    brno_dir: Optional[Sequence[str]] = None,
    rapid7_fdns: Optional[str] = None,
    maxmind_city: Optional[str] = None,
    maxmind_asn: Optional[str] = None,
    blocklist: Optional[Sequence[str]] = None,
    tranco: Optional[str] = None,
    rir_dump: Optional[Sequence[str]] = None,
    rdns_dump: Optional[str] = None,
    rdap_dump: Optional[Sequence[str]] = None,
    zone: Optional[Sequence[str]] = None,
    ipthreat: Optional[Sequence[str]] = None,
    peeringdb: Optional[str] = None,
    ct_dump: Optional[Sequence[str]] = None,
    fields: Optional[List[str]] = None,
    fmt: str = "parquet",
    force: Optional[Iterable[str]] = None,
) -> dict:
    force_set: Set[str] = set(force or [])
    store = Store(db)
    try:
        if "normalize" in force_set or not store.stage_done("normalize"):
            stage_normalize(store, input_path)
        else:
            _log("[normalize] already done, skipping")

        stage_brno(store, brno_dir, force_set)
        stage_rapid7(store, rapid7_fdns, force_set)
        stage_zone(store, zone, force_set)            # forward DNS -> IPs
        stage_geo(store, maxmind_city, maxmind_asn, force_set)
        stage_netwhois(store, rir_dump, force_set)
        stage_peeringdb(store, peeringdb, force_set)  # needs ASN
        stage_rdns(store, rdns_dump, force_set)
        stage_threat(store, blocklist, force_set)
        stage_ipthreat(store, ipthreat, force_set)    # needs IPs
        stage_tranco(store, tranco, force_set)
        stage_ct(store, ct_dump, force_set)
        stage_rdap(store, rdap_dump, force_set)
        return stage_export(store, output, fields, fmt)
    finally:
        store.close()
