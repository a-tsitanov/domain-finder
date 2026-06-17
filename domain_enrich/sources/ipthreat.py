"""IP/CIDR-based threat matching (offline).

Some feeds are keyed by IP or network rather than domain: Feodo Tracker (C2
IPs), Spamhaus DROP (hijacked CIDR blocks), SSLBL (IPs). This stage loads those
into an exact-IP set + a CIDR list and flags any domain whose resolved IP falls
in them. Complements the domain-keyed ``threat`` stage.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Dict, Iterable, List, Set, Tuple

from .blocklists import label_for_list, _LABEL_RANK

_TOKEN = re.compile(r"[0-9a-fA-F:.]+(?:/\d{1,3})?")


def _list_name(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


class IpThreat:
    """Exact-IP set + CIDR list, queryable by IP -> matching list names."""

    def __init__(self):
        self.exact: Dict[str, Set[str]] = {}
        self.cidrs: List[Tuple[ipaddress._BaseNetwork, str]] = []

    def add(self, path: str) -> None:
        name = _list_name(path)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line[0] in "#;%":
                    continue
                m = _TOKEN.match(line)
                if not m:
                    continue
                tok = m.group(0)
                try:
                    net = ipaddress.ip_network(tok, strict=False)
                except ValueError:
                    continue
                if net.prefixlen == net.max_prefixlen:
                    self.exact.setdefault(str(net.network_address), set()).add(name)
                else:
                    self.cidrs.append((net, name))

    def match(self, ip: str) -> Set[str]:
        out: Set[str] = set(self.exact.get(ip, ()))
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return out
        for net, name in self.cidrs:
            if addr.version == net.version and addr in net:
                out.add(name)
        return out


def run_ipthreat(store, paths, batch_size: int = 5000, progress=None) -> int:
    """Flag domains whose IPs appear in IP/CIDR threat feeds."""
    matcher = IpThreat()
    for p in paths:
        matcher.add(p)

    matched = 0
    work = list(store.iter_ips(flag="s_ipthreat"))
    with store.batch():
        for domain, ips in work:
            names: Set[str] = set()
            for ip in ips:
                names |= matcher.match(ip)
            if names:
                label = max((label_for_list(n) for n in names),
                            key=lambda l: _LABEL_RANK.get(l, 0))
                store.update_threat(domain, threat_label=label,
                                    threat_sources=",".join(sorted(names)))
                matched += 1
                if progress is not None:
                    progress.update(1)
            store.mark_row_done(domain, "s_ipthreat")
    return matched
