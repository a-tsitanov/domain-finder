"""Offline RIR (RIPE/ARIN/APNIC/LACNIC/AFRINIC) network-whois adapter.

RIRs publish their whois database as downloadable RPSL text dumps. This parses
the ``inetnum`` / ``inet6num`` objects (plus ``organisation`` and abuse
``role``/``person`` objects to resolve the org name and abuse mailbox) and
answers, for any IP, the most specific network it falls in — i.e. the
"Network Whois record" you get from tools like Domain Dossier, but offline.

No network access: you download the dump once and join against it.
"""

from __future__ import annotations

import gzip
import ipaddress
from typing import Dict, Iterable, List, Optional, Tuple


# Netname/descr markers for ranges a RIR lists but does not actually manage
# (delegated to another RIR, e.g. ARIN). Treated as "no data".
_PLACEHOLDER_NETNAMES = ("NON-RIPE-NCC-MANAGED", "IANA-NETBLOCK", "IANA-BLK",
                         "IANA-BLOCK", "NON-APNIC", "NON-AFRINIC", "AFRINIC-NETBLOCK")
_PLACEHOLDER_DESCR = ("not managed by", "not allocated", "not been allocated",
                      "ipv4 address block not", "placeholder", "all ipv4 addresses")


def _is_placeholder(netname: str, descr: str) -> bool:
    n = (netname or "").upper()
    if any(n.startswith(p) for p in _PLACEHOLDER_NETNAMES):
        return True
    d = (descr or "").lower()
    return any(m in d for m in _PLACEHOLDER_DESCR)


def _open(path: str):
    """Open an RIR dump, transparently handling gzip."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _parse_objects(lines: Iterable[str]):
    """Yield RPSL objects as {key: [values]} dicts (split on blank lines).

    Streams a line iterator so multi-GB dumps never load fully into memory.
    """
    obj: Dict[str, List[str]] = {}
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            if obj:
                yield obj
                obj = {}
            continue
        if line[0] in "#%":  # comment lines in RIR dumps
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if val:
            obj.setdefault(key, []).append(val)
    if obj:
        yield obj


def _range_bounds(value: str) -> Optional[Tuple[int, int, int]]:
    """Return (start_int, end_int, version) for an inetnum/inet6num value."""
    try:
        if " - " in value:
            lo, hi = (p.strip() for p in value.split(" - ", 1))
            a, b = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
            return int(a), int(b), a.version
        if "/" in value:
            net = ipaddress.ip_network(value.strip(), strict=False)
            return int(net.network_address), int(net.broadcast_address), net.version
    except ValueError:
        return None
    return None


class RirIndex:
    """In-memory index of network objects, queryable by IP."""

    # Prefix bits used to bucket ranges for O(1)-ish point lookup.
    _SHIFT = {4: 16, 6: 96}        # IPv4 -> /16 buckets, IPv6 -> /32 buckets
    _MAX_BUCKETS = 1024            # ranges wider than this go in a small fallback

    def __init__(self):
        # (start, end, version, range_str, netname, country, org_handle,
        #  abuse_handles, descr)
        self.nets: List[Tuple] = []
        self.orgs: Dict[str, dict] = {}        # handle -> {org-name, abuse-c}
        self.contacts: Dict[str, str] = {}     # nic-hdl / irt -> abuse email
        # prefix -> [net index]; plus a fallback list for very wide ranges.
        self._buckets: Dict[int, Dict[int, List[int]]] = {4: {}, 6: {}}
        self._wide: Dict[int, List[int]] = {4: [], 6: []}

    def _index_net(self, idx: int, start: int, end: int, ver: int) -> None:
        shift = self._SHIFT[ver]
        lo, hi = start >> shift, end >> shift
        if hi - lo >= self._MAX_BUCKETS:
            self._wide[ver].append(idx)
            return
        buckets = self._buckets[ver]
        for key in range(lo, hi + 1):
            buckets.setdefault(key, []).append(idx)

    def add_text(self, text: str) -> None:
        self.add_lines(text.splitlines())

    def add_lines(self, lines: Iterable[str]) -> None:
        for obj in _parse_objects(lines):
            if "inetnum" in obj or "inet6num" in obj:
                raw = (obj.get("inetnum") or obj.get("inet6num"))[0]
                bounds = _range_bounds(raw)
                if not bounds:
                    continue
                start, end, ver = bounds
                # A range covering the entire address space is always a
                # catch-all placeholder (IANA-BLOCK / ROOT / 0.0.0.0/0).
                full = (1 << (32 if ver == 4 else 128)) - 1
                if start == 0 and end == full:
                    continue
                netname = (obj.get("netname") or [""])[0]
                descr = (obj.get("descr") or [""])[0]
                if _is_placeholder(netname, descr):
                    continue  # range delegated elsewhere -> treat as no data
                # Abuse can be referenced via abuse-c (RIPE) or mnt-irt (APNIC).
                abuse_handles = list(obj.get("abuse-c", [])) + list(obj.get("mnt-irt", []))
                idx = len(self.nets)
                self.nets.append((
                    start, end, ver, raw,
                    netname,
                    (obj.get("country") or [""])[0],
                    (obj.get("org") or [""])[0],
                    abuse_handles,
                    descr,
                ))
                self._index_net(idx, start, end, ver)
            elif "organisation" in obj:
                handle = obj["organisation"][0]
                self.orgs[handle] = {
                    "org-name": (obj.get("org-name") or [""])[0],
                    "abuse-c": (obj.get("abuse-c") or [""])[0],
                }
            elif "irt" in obj:  # APNIC abuse object
                mailbox = (obj.get("abuse-mailbox") or obj.get("e-mail") or [""])[0]
                if mailbox:
                    self.contacts[obj["irt"][0]] = mailbox
            elif "nic-hdl" in obj:  # RIPE role/person
                mailbox = (obj.get("abuse-mailbox") or obj.get("e-mail") or [""])[0]
                if mailbox:
                    self.contacts[obj["nic-hdl"][0]] = mailbox

    def lookup(self, ip: str) -> Dict[str, str]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        ip_int, ver = int(addr), addr.version

        # Only scan ranges in this IP's prefix bucket (+ the few wide ranges),
        # not the whole table -> O(bucket size) instead of O(all nets).
        key = ip_int >> self._SHIFT[ver]
        candidates = self._buckets[ver].get(key, ())
        best = None
        best_size = None
        for idx in (*candidates, *self._wide[ver]):
            net = self.nets[idx]
            start, end = net[0], net[1]
            if ip_int < start or ip_int > end:
                continue
            size = end - start
            if best_size is None or size < best_size:  # most specific wins
                best_size = size
                best = net
        if best is None:
            return {}

        _, _, _, raw, netname, country, org_handle, abuse_handles, descr = best
        out: Dict[str, str] = {"net_range": raw}
        if netname:
            out["net_name"] = netname
        if country:
            out["net_country"] = country

        org = self.orgs.get(org_handle)
        if org and org.get("org-name"):
            out["net_org"] = org["org-name"]
        elif descr:  # APNIC inetnums often lack org: but carry descr
            out["net_org"] = descr

        # Resolve abuse: prefer the org's abuse-c, then the inetnum's handles.
        candidates = []
        if org and org.get("abuse-c"):
            candidates.append(org["abuse-c"])
        candidates.extend(abuse_handles)
        for h in candidates:
            if h in self.contacts:
                out["net_abuse_email"] = self.contacts[h]
                break
        return out


def build_rir_index(paths: Iterable[str]) -> RirIndex:
    idx = RirIndex()
    for path in paths:
        try:
            with _open(path) as fh:
                idx.add_lines(fh)
        except (OSError, gzip.BadGzipFile, EOFError) as exc:
            # A corrupt/truncated dump must not sink the whole stage.
            import sys
            print(f"WARNING: rir: skipping unreadable {path}: {exc}",
                  file=sys.stderr)
    return idx


def run_rir(store, paths, progress=None) -> int:
    """Resolve network-whois for every domain with IPs and pending netwhois."""
    idx = build_rir_index(list(paths))
    matched = 0
    work = list(store.iter_ips(flag="s_netwhois"))
    with store.batch():
        for domain, ips in work:
            data = {}
            for ip in ips:
                found = idx.lookup(ip)
                if found:
                    data = found
                    break
            if data:
                store.update_netwhois(domain, **data)
                matched += 1
                if progress is not None:
                    progress.update(1)
            store.mark_row_done(domain, "s_netwhois")
    return matched
