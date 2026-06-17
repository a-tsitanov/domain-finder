"""Flatten the store into a single wide table and write parquet and/or CSV.

JSON columns are expanded into flat string/scalar columns. Output is written in
chunks so a 2M-row table never has to live in memory at once.
"""

from __future__ import annotations

import csv as csvmod
import json
from typing import Dict, Iterator, List, Optional

# Canonical flat output schema, in display order.
FLAT_FIELDS: List[str] = [
    "domain", "original",
    # DNS / address lookup
    "a", "aaaa", "ns", "mx", "txt", "cname", "soa", "ptr", "ips",
    # TLS
    "tls_cipher", "tls_protocol", "tls_sans",
    # GeoIP / ASN
    "geo_country", "geo_city", "geo_lat", "geo_lon",
    "asn", "asn_org", "asn_network", "asn_type",
    # Network whois (RIR)
    "net_range", "net_name", "net_org", "net_country", "net_abuse_email",
    # Popularity
    "popularity_rank",
    # Domain whois (RDAP)
    "registrar", "registrar_ianaid", "whois_server",
    "created_date", "updated_date", "expires_date",
    "registrant_org", "registrant_country", "abuse_email",
    "domain_status", "dnssec", "nameservers",
    # Threat
    "threat_label", "threat_type", "threat_sources",
]

_LIST_COLUMNS = ("a", "aaaa", "ns", "mx", "txt", "cname", "ptr", "ips", "nameservers")


def available_fields() -> List[str]:
    return list(FLAT_FIELDS)


def _loads(value):
    if value is None or value == "":
        return None
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def _join(value) -> Optional[str]:
    parsed = _loads(value)
    if parsed is None:
        return None
    if isinstance(parsed, list):
        return ";".join(str(x) for x in parsed)
    return str(parsed)


def _extract_sans(tls: dict) -> Optional[str]:
    """Pull SAN entries out of a TLS blob, tolerating a few shapes."""
    sans: List[str] = []
    for key, val in tls.items():
        if "san" in key.lower() and isinstance(val, list):
            sans.extend(str(x) for x in val)
    # Some dumps nest SANs inside a certificate chain.
    chain = tls.get("certificates") or tls.get("chain")
    if isinstance(chain, list):
        for cert in chain:
            if isinstance(cert, dict):
                for key, val in cert.items():
                    if "san" in key.lower() and isinstance(val, list):
                        sans.extend(str(x) for x in val)
    seen = list(dict.fromkeys(sans))
    return ";".join(seen) if seen else None


def flatten_row(row: Dict) -> Dict:
    """Turn a raw store row into the flat output schema."""
    flat: Dict = {}
    flat["domain"] = row.get("domain")
    flat["original"] = row.get("original")

    for col in _LIST_COLUMNS:
        flat[col] = _join(row.get(col))

    tls = _loads(row.get("tls"))
    if isinstance(tls, dict):
        flat["tls_cipher"] = tls.get("cipher")
        flat["tls_protocol"] = tls.get("protocol")
        flat["tls_sans"] = _extract_sans(tls)
    else:
        flat["tls_cipher"] = flat["tls_protocol"] = flat["tls_sans"] = None
    # Prefer the dedicated SAN column (Certificate Transparency) if present.
    san = _join(row.get("san"))
    if san:
        flat["tls_sans"] = san

    flat["soa"] = row.get("soa")

    for col in ("geo_country", "geo_city", "geo_lat", "geo_lon",
                "asn", "asn_org", "asn_network", "asn_type",
                "net_range", "net_name", "net_org", "net_country", "net_abuse_email",
                "popularity_rank",
                "registrar", "registrar_ianaid", "whois_server",
                "created_date", "updated_date", "expires_date",
                "registrant_org", "registrant_country", "abuse_email",
                "domain_status", "dnssec",
                "threat_label", "threat_type", "threat_sources"):
        flat[col] = row.get(col)

    return flat


def _iter_flat(store, fields: List[str], batch: int) -> Iterator[Dict]:
    for row in store.iter_rows(batch):
        flat = flatten_row(row)
        yield {f: flat.get(f) for f in fields}


def _write_csv(store, path: str, fields: List[str], batch: int) -> int:
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csvmod.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for rec in _iter_flat(store, fields, batch):
            writer.writerow(rec)
            n += 1
    return n


def _write_parquet(store, path: str, fields: List[str], batch: int) -> int:
    import pyarrow as pa
    import pyarrow.parquet as pq

    writer = None
    n = 0
    chunk: List[Dict] = []

    def flush(rows):
        nonlocal writer
        if not rows:
            return
        cols = {f: [r[f] for r in rows] for f in fields}
        table = pa.table(cols)
        if writer is None:
            writer = pq.ParquetWriter(path, table.schema)
        writer.write_table(table)

    try:
        for rec in _iter_flat(store, fields, batch):
            chunk.append(rec)
            n += 1
            if len(chunk) >= batch:
                flush(chunk)
                chunk = []
        flush(chunk)
        # Empty result: still emit a valid file with the schema.
        if writer is None:
            empty = pa.table({f: pa.array([], type=pa.string()) for f in fields})
            pq.write_table(empty, path)
    finally:
        if writer is not None:
            writer.close()
    return n


def export(store, output: str, fields: Optional[List[str]] = None,
           fmt: str = "parquet", batch: int = 5000) -> Dict[str, int]:
    """Write the flattened table. ``fmt`` is parquet | csv | both.

    For ``both`` the output extension is swapped to .parquet/.csv. Returns a
    map of format -> rows written.
    """
    fields = fields or available_fields()
    unknown = [f for f in fields if f not in FLAT_FIELDS]
    if unknown:
        raise ValueError(f"unknown field(s): {', '.join(unknown)}")

    results: Dict[str, int] = {}
    if fmt in ("parquet", "both"):
        path = output if fmt == "parquet" else _swap_ext(output, ".parquet")
        results["parquet"] = _write_parquet(store, path, fields, batch)
    if fmt in ("csv", "both"):
        path = output if fmt == "csv" else _swap_ext(output, ".csv")
        results["csv"] = _write_csv(store, path, fields, batch)
    if not results:
        raise ValueError(f"unknown format: {fmt}")
    return results


def _swap_ext(path: str, ext: str) -> str:
    base = path.rsplit(".", 1)[0] if "." in path.rsplit("/", 1)[-1] else path
    return base + ext
