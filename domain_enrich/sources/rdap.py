"""RDAP (Registration Data Access Protocol) parsing — fully offline.

This module does NOT talk to the network. It parses RDAP JSON objects that
arrive from an offline source: either the ``rdap`` field already present in the
Brno dataset, or a separate offline RDAP dump (one JSON object per line, or a
JSON array). It turns the nested RDAP/jCard structure into the flat domain-whois
columns of the store (registrar, dates, registrant, status, DNSSEC, NS).
"""

from __future__ import annotations

import glob
import json
import os
from typing import Dict, Iterable, List, Optional

from ..normalize import normalize_domain

_EVENT_MAP = {
    "registration": "created_date",
    "last changed": "updated_date",
    "last update of rdap database": None,  # ignore
    "expiration": "expires_date",
}


def _vcard_map(entity: dict) -> Dict[str, object]:
    """Flatten a jCard (vcardArray) into {property: value}."""
    out: Dict[str, object] = {}
    vca = entity.get("vcardArray")
    if not (isinstance(vca, list) and len(vca) == 2 and isinstance(vca[1], list)):
        return out
    for item in vca[1]:
        if isinstance(item, list) and len(item) >= 4:
            out[item[0]] = item[3]
    return out


def _entities_by_role(entities, role: str):
    """Return entities carrying ``role`` from either RDAP shape.

    Standard RDAP: a list of entity dicts each with a ``roles`` array (abuse may
    be nested inside the registrar). Brno: a dict keyed by role -> list.
    """
    if isinstance(entities, dict):
        return entities.get(role) or []
    out = []

    def walk(ents):
        if not isinstance(ents, list):
            return
        for ent in ents:
            if isinstance(ent, dict):
                if role in (ent.get("roles") or []):
                    out.append(ent)
                walk(ent.get("entities"))
    walk(entities)
    return out


def _entity_name(ent: dict) -> Optional[str]:
    """Entity display name: jCard fn/org (standard) or direct name/org (Brno)."""
    vc = _vcard_map(ent)
    return vc.get("org") or vc.get("fn") or ent.get("name") or ent.get("org") or None


def _entity_email(ent: dict) -> Optional[str]:
    return _vcard_map(ent).get("email") or ent.get("email") or None


def _entity_iana(ent: dict) -> Optional[str]:
    for pid in ent.get("publicIds") or []:
        if isinstance(pid, dict) and "IANA" in str(pid.get("type", "")):
            return str(pid.get("identifier"))
    return str(ent["handle"]) if ent.get("handle") else None


def _unwrap_date(v):
    if isinstance(v, dict):
        inner = v.get("$date", v)
        return _unwrap_date(inner) if isinstance(inner, dict) else inner
    return v


def parse_rdap(doc: Optional[dict]) -> Dict[str, object]:
    """Extract flat whois fields from an RDAP object (standard or Brno shape)."""
    if not isinstance(doc, dict) or not doc:
        return {}

    out: Dict[str, object] = {}
    entities = doc.get("entities") or []

    # Registrar (+ IANA id).
    regs = _entities_by_role(entities, "registrar")
    if regs:
        name = _entity_name(regs[0])
        if name:
            out["registrar"] = name
        iana = _entity_iana(regs[0])
        if iana:
            out["registrar_ianaid"] = iana

    # Abuse email (top-level role, or nested under registrar in standard RDAP).
    abuse = _entities_by_role(entities, "abuse")
    if abuse:
        email = _entity_email(abuse[0])
        if email:
            out["abuse_email"] = email

    # Registrant org + country.
    registrant = _entities_by_role(entities, "registrant")
    if registrant:
        name = _entity_name(registrant[0])
        if name:
            out["registrant_org"] = name
        adr = _vcard_map(registrant[0]).get("adr")
        if isinstance(adr, list) and len(adr) >= 7 and adr[6]:
            out["registrant_country"] = adr[6]
        elif registrant[0].get("country"):
            out["registrant_country"] = registrant[0]["country"]

    # Dates: Brno direct fields first, then standard events[].
    for col, brno_key, action in (
        ("created_date", "registration_date", "registration"),
        ("updated_date", "last_changed_date", "last changed"),
        ("expires_date", "expiration_date", "expiration"),
    ):
        v = _unwrap_date(doc.get(brno_key))
        if v:
            out[col] = v
    for ev in doc.get("events") or []:
        if not isinstance(ev, dict):
            continue
        col = _EVENT_MAP.get(str(ev.get("eventAction", "")).lower())
        if col and col not in out and ev.get("eventDate"):
            out[col] = _unwrap_date(ev["eventDate"])

    # Status.
    status = doc.get("status")
    if isinstance(status, list) and status:
        out["domain_status"] = ";".join(str(s) for s in status)

    # DNSSEC: standard secureDNS.delegationSigned, or Brno top-level bool.
    secure = doc.get("secureDNS")
    if isinstance(secure, dict) and "delegationSigned" in secure:
        out["dnssec"] = "signedDelegation" if secure["delegationSigned"] else "unsigned"
    elif isinstance(doc.get("dnssec"), bool):
        out["dnssec"] = "signedDelegation" if doc["dnssec"] else "unsigned"

    # Nameservers: list of {ldhName} (standard) or list of strings (Brno).
    ns = []
    for n in doc.get("nameservers") or []:
        if isinstance(n, str):
            ns.append(n.lower().rstrip("."))
        elif isinstance(n, dict) and n.get("ldhName"):
            ns.append(n["ldhName"].lower().rstrip("."))
    if ns:
        out["nameservers"] = ns

    # Whois server.
    if doc.get("port43"):
        out["whois_server"] = doc["port43"]
    elif doc.get("whois_server"):
        out["whois_server"] = doc["whois_server"]

    return out


# -- offline dump stage --------------------------------------------------
def _collect(paths: Iterable[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            out.extend(sorted(glob.glob(os.path.join(p, "*"))))
        else:
            out.extend(sorted(glob.glob(p)) or ([p] if os.path.exists(p) else []))
    return [f for f in out if os.path.isfile(f)]


def _iter_objects(path: str):
    """Yield JSON objects from a dump that is either JSON-lines or an array."""
    import ijson
    with open(path, "rb") as fh:
        head = fh.read(64).lstrip()
        fh.seek(0)
        if head[:1] == b"[":
            yield from ijson.items(fh, "item")
        else:
            text = fh.read().decode("utf-8", "replace")
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue


def _domain_of(doc: dict) -> Optional[str]:
    raw = doc.get("ldhName") or doc.get("domain") or doc.get("domain_name")
    return normalize_domain(raw) if raw else None


def run_rdap(store, paths, force: bool = False, progress=None) -> int:
    """Apply an offline RDAP dump to the working set. Returns # matched."""
    work = store.all_domains()
    matched = 0
    with store.batch():
        for path in _collect(list(paths)):
            for doc in _iter_objects(path):
                if not isinstance(doc, dict):
                    continue
                domain = _domain_of(doc)
                if domain is None or domain not in work:
                    continue
                fields = parse_rdap(doc)
                if fields:
                    store.update_rdap(domain, **fields)
                    matched += 1
                    if progress is not None:
                        progress.update(1)
        store.conn.execute("UPDATE domains SET s_rdap = 1 WHERE s_rdap = 0")
    return matched
