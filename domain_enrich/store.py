"""SQLite intermediate store for the enrichment pipeline.

One row == one domain. Each stage writes its own columns and flips a per-row
"done" flag, which makes every stage independently resumable: re-running a
stage skips rows already marked done. Coarse stage status lives in ``meta``.

All multi-value columns (A/AAAA/NS/MX/ips, tls, rdap, ip_data) are stored as
JSON text. Writers use COALESCE so that a later, poorer source never clobbers
a value already supplied by a richer one.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

# Per-row "stage done" flag columns.
ROW_FLAGS = ("s_brno", "s_rapid7", "s_geo", "s_threat", "s_tranco",
             "s_rdns", "s_rdap", "s_netwhois", "s_ipthreat", "s_peeringdb",
             "s_ct", "s_zone")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    domain        TEXT PRIMARY KEY,   -- normalized
    original      TEXT,
    -- DNS / IP (JSON arrays)
    a             TEXT,
    aaaa          TEXT,
    ns            TEXT,
    mx            TEXT,
    ips           TEXT,               -- unique IPs derived from A/AAAA
    -- TLS / RDAP / raw ip metadata (JSON blobs)
    tls           TEXT,
    rdap          TEXT,
    ip_data       TEXT,
    -- GeoIP / ASN
    geo_country   TEXT,
    geo_city      TEXT,
    geo_lat       REAL,
    geo_lon       REAL,
    asn           INTEGER,
    asn_org       TEXT,
    asn_network   TEXT,
    asn_type      TEXT,                -- PeeringDB network type
    -- Subject Alternative Names (Certificate Transparency)
    san           TEXT,
    -- Threat
    threat_label  TEXT,
    threat_type   TEXT,
    threat_sources TEXT,
    -- Live DNS resolve (dossier "Address lookup" + "DNS records")
    txt           TEXT,
    soa           TEXT,
    cname         TEXT,
    ptr           TEXT,
    -- Popularity (Tranco)
    popularity_rank INTEGER,
    -- Domain Whois (RDAP)
    registrar        TEXT,
    registrar_ianaid TEXT,
    whois_server     TEXT,
    created_date     TEXT,
    updated_date     TEXT,
    expires_date     TEXT,
    registrant_org   TEXT,
    registrant_country TEXT,
    abuse_email      TEXT,
    domain_status    TEXT,
    dnssec           TEXT,
    nameservers      TEXT,
    -- Network Whois (IP RDAP / RIR)
    net_range        TEXT,
    net_name         TEXT,
    net_org          TEXT,
    net_country      TEXT,
    net_abuse_email  TEXT,
    -- per-row stage flags
    s_brno        INTEGER NOT NULL DEFAULT 0,
    s_rapid7      INTEGER NOT NULL DEFAULT 0,
    s_geo         INTEGER NOT NULL DEFAULT 0,
    s_threat      INTEGER NOT NULL DEFAULT 0,
    s_tranco      INTEGER NOT NULL DEFAULT 0,
    s_rdns        INTEGER NOT NULL DEFAULT 0,
    s_rdap        INTEGER NOT NULL DEFAULT 0,
    s_netwhois    INTEGER NOT NULL DEFAULT 0,
    s_ipthreat    INTEGER NOT NULL DEFAULT 0,
    s_peeringdb   INTEGER NOT NULL DEFAULT 0,
    s_ct          INTEGER NOT NULL DEFAULT 0,
    s_zone        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS meta (
    stage   TEXT PRIMARY KEY,
    status  TEXT
);
"""

# Indexes are created AFTER migration so they can reference columns that an
# older DB only gains during _migrate().
_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_s_geo ON domains(s_geo);
CREATE INDEX IF NOT EXISTS idx_s_brno ON domains(s_brno);
CREATE INDEX IF NOT EXISTS idx_s_rapid7 ON domains(s_rapid7);
CREATE INDEX IF NOT EXISTS idx_s_threat ON domains(s_threat);
CREATE INDEX IF NOT EXISTS idx_s_tranco ON domains(s_tranco);
CREATE INDEX IF NOT EXISTS idx_s_rdns ON domains(s_rdns);
CREATE INDEX IF NOT EXISTS idx_s_rdap ON domains(s_rdap);
CREATE INDEX IF NOT EXISTS idx_s_netwhois ON domains(s_netwhois);
CREATE INDEX IF NOT EXISTS idx_s_ipthreat ON domains(s_ipthreat);
CREATE INDEX IF NOT EXISTS idx_s_peeringdb ON domains(s_peeringdb);
CREATE INDEX IF NOT EXISTS idx_s_ct ON domains(s_ct);
CREATE INDEX IF NOT EXISTS idx_s_zone ON domains(s_zone);
"""

# (column, SQL type/default) for columns that may be missing in older DBs.
_MIGRATE_COLUMNS = [
    ("txt", "TEXT"), ("soa", "TEXT"), ("cname", "TEXT"), ("ptr", "TEXT"),
    ("popularity_rank", "INTEGER"),
    ("registrar", "TEXT"), ("registrar_ianaid", "TEXT"), ("whois_server", "TEXT"),
    ("created_date", "TEXT"), ("updated_date", "TEXT"), ("expires_date", "TEXT"),
    ("registrant_org", "TEXT"), ("registrant_country", "TEXT"),
    ("abuse_email", "TEXT"), ("domain_status", "TEXT"), ("dnssec", "TEXT"),
    ("nameservers", "TEXT"),
    ("net_range", "TEXT"), ("net_name", "TEXT"), ("net_org", "TEXT"),
    ("net_country", "TEXT"), ("net_abuse_email", "TEXT"),
    ("asn_type", "TEXT"), ("san", "TEXT"),
    ("s_tranco", "INTEGER NOT NULL DEFAULT 0"),
    ("s_rdns", "INTEGER NOT NULL DEFAULT 0"),
    ("s_rdap", "INTEGER NOT NULL DEFAULT 0"),
    ("s_netwhois", "INTEGER NOT NULL DEFAULT 0"),
    ("s_ipthreat", "INTEGER NOT NULL DEFAULT 0"),
    ("s_peeringdb", "INTEGER NOT NULL DEFAULT 0"),
    ("s_ct", "INTEGER NOT NULL DEFAULT 0"),
    ("s_zone", "INTEGER NOT NULL DEFAULT 0"),
]


def _dumps(value) -> Optional[str]:
    """JSON-encode a list/dict, or pass through None. Empty -> None."""
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        value = sorted(value) if isinstance(value, set) else list(value)
        if not value:
            return None
    return json.dumps(value, ensure_ascii=False, default=str,
                      sort_keys=isinstance(value, dict))


class Store:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(_SCHEMA)
        self._migrate()
        self.conn.executescript(_INDEXES)
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns missing from DBs created by an older version."""
        existing = {r[1] for r in self.conn.execute("PRAGMA table_info(domains)")}
        for name, decl in _MIGRATE_COLUMNS:
            if name not in existing:
                self.conn.execute(f"ALTER TABLE domains ADD COLUMN {name} {decl}")

    def close(self) -> None:
        self.conn.close()

    # -- context manager -------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @contextmanager
    def batch(self):
        """One explicit transaction; commit on success, rollback on error."""
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # -- ingest ----------------------------------------------------------
    def add_domains(self, pairs: Iterable[Tuple[str, str]]) -> int:
        """INSERT OR IGNORE (normalized, original). Returns # of new rows."""
        before = self._count()
        with self.batch() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO domains(domain, original) VALUES (?, ?)",
                pairs,
            )
        return self._count() - before

    def _count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]

    # -- reads -----------------------------------------------------------
    def all_domains(self) -> set:
        return {r[0] for r in self.conn.execute("SELECT domain FROM domains")}

    def iter_rows(self, batch: int = 5000) -> Iterator[dict]:
        cur = self.conn.execute("SELECT * FROM domains")
        while True:
            rows = cur.fetchmany(batch)
            if not rows:
                break
            for r in rows:
                yield dict(r)

    def iter_rows_pending(self, flag: str, batch: int = 5000) -> Iterator[dict]:
        """Yield rows whose per-row stage ``flag`` is not yet set."""
        if flag not in ROW_FLAGS:
            raise ValueError(f"unknown row flag: {flag}")
        cur = self.conn.execute(f"SELECT * FROM domains WHERE {flag} = 0")
        while True:
            rows = cur.fetchmany(batch)
            if not rows:
                break
            for r in rows:
                yield dict(r)

    def iter_ips(self, batch: int = 5000, flag: str = "s_geo") -> Iterator[Tuple[str, List[str]]]:
        """Yield (domain, ips) for domains with IPs whose ``flag`` is pending."""
        if flag not in ROW_FLAGS:
            raise ValueError(f"unknown row flag: {flag}")
        cur = self.conn.execute(
            "SELECT domain, ips FROM domains "
            f"WHERE ips IS NOT NULL AND ips != '' AND {flag} = 0"
        )
        while True:
            rows = cur.fetchmany(batch)
            if not rows:
                break
            for domain, ips in rows:
                try:
                    parsed = json.loads(ips)
                except (TypeError, ValueError):
                    continue
                if parsed:
                    yield domain, parsed

    def iter_asns(self, batch: int = 5000, flag: str = "s_peeringdb"):
        """Yield (domain, asn) for domains with an ASN whose ``flag`` is pending."""
        if flag not in ROW_FLAGS:
            raise ValueError(f"unknown row flag: {flag}")
        cur = self.conn.execute(
            f"SELECT domain, asn FROM domains WHERE asn IS NOT NULL AND {flag} = 0"
        )
        while True:
            rows = cur.fetchmany(batch)
            if not rows:
                break
            for domain, asn in rows:
                yield domain, asn

    # -- writers (COALESCE: keep existing richer value) ------------------
    def update_dns(self, domain, a=None, aaaa=None, ns=None, mx=None, ips=None,
                   tls=None, rdap=None, ip_data=None, txt=None, soa=None,
                   cname=None, ptr=None) -> None:
        self.conn.execute(
            """
            UPDATE domains SET
                a       = COALESCE(a, ?),
                aaaa    = COALESCE(aaaa, ?),
                ns      = COALESCE(ns, ?),
                mx      = COALESCE(mx, ?),
                ips     = COALESCE(ips, ?),
                tls     = COALESCE(tls, ?),
                rdap    = COALESCE(rdap, ?),
                ip_data = COALESCE(ip_data, ?),
                txt     = COALESCE(txt, ?),
                soa     = COALESCE(soa, ?),
                cname   = COALESCE(cname, ?),
                ptr     = COALESCE(ptr, ?)
            WHERE domain = ?
            """,
            (_dumps(a), _dumps(aaaa), _dumps(ns), _dumps(mx), _dumps(ips),
             _dumps(tls), _dumps(rdap), _dumps(ip_data), _dumps(txt), soa,
             _dumps(cname), _dumps(ptr), domain),
        )

    def update_geo(self, domain, geo_country=None, geo_city=None, geo_lat=None,
                   geo_lon=None, asn=None, asn_org=None, asn_network=None) -> None:
        self.conn.execute(
            """
            UPDATE domains SET
                geo_country = COALESCE(geo_country, ?),
                geo_city    = COALESCE(geo_city, ?),
                geo_lat     = COALESCE(geo_lat, ?),
                geo_lon     = COALESCE(geo_lon, ?),
                asn         = COALESCE(asn, ?),
                asn_org     = COALESCE(asn_org, ?),
                asn_network = COALESCE(asn_network, ?)
            WHERE domain = ?
            """,
            (geo_country, geo_city, geo_lat, geo_lon, asn, asn_org, asn_network, domain),
        )

    def update_threat(self, domain, threat_label=None, threat_type=None,
                      threat_sources=None) -> None:
        self.conn.execute(
            """
            UPDATE domains SET
                threat_label   = COALESCE(threat_label, ?),
                threat_type    = COALESCE(threat_type, ?),
                threat_sources = COALESCE(threat_sources, ?)
            WHERE domain = ?
            """,
            (threat_label, threat_type, threat_sources, domain),
        )

    def update_tranco(self, domain, popularity_rank=None) -> None:
        # Keep the best (smallest) rank seen across popularity lists.
        self.conn.execute(
            "UPDATE domains SET popularity_rank = CASE "
            "WHEN popularity_rank IS NULL OR ? < popularity_rank THEN ? "
            "ELSE popularity_rank END WHERE domain = ?",
            (popularity_rank, popularity_rank, domain),
        )

    def update_asn_info(self, domain, asn_org=None, asn_type=None) -> None:
        self.conn.execute(
            "UPDATE domains SET asn_org = COALESCE(asn_org, ?), "
            "asn_type = COALESCE(asn_type, ?) WHERE domain = ?",
            (asn_org, asn_type, domain),
        )

    def update_san(self, domain, san=None, tls=None) -> None:
        self.conn.execute(
            "UPDATE domains SET san = COALESCE(san, ?), tls = COALESCE(tls, ?) "
            "WHERE domain = ?",
            (_dumps(san), _dumps(tls), domain),
        )

    def update_rdap(self, domain, registrar=None, registrar_ianaid=None,
                    whois_server=None, created_date=None, updated_date=None,
                    expires_date=None, registrant_org=None, registrant_country=None,
                    abuse_email=None, domain_status=None, dnssec=None,
                    nameservers=None) -> None:
        self.conn.execute(
            """
            UPDATE domains SET
                registrar        = COALESCE(registrar, ?),
                registrar_ianaid = COALESCE(registrar_ianaid, ?),
                whois_server     = COALESCE(whois_server, ?),
                created_date     = COALESCE(created_date, ?),
                updated_date     = COALESCE(updated_date, ?),
                expires_date     = COALESCE(expires_date, ?),
                registrant_org   = COALESCE(registrant_org, ?),
                registrant_country = COALESCE(registrant_country, ?),
                abuse_email      = COALESCE(abuse_email, ?),
                domain_status    = COALESCE(domain_status, ?),
                dnssec           = COALESCE(dnssec, ?),
                nameservers      = COALESCE(nameservers, ?)
            WHERE domain = ?
            """,
            (registrar, registrar_ianaid, whois_server, created_date, updated_date,
             expires_date, registrant_org, registrant_country, abuse_email,
             domain_status, dnssec, _dumps(nameservers), domain),
        )

    def update_netwhois(self, domain, net_range=None, net_name=None, net_org=None,
                        net_country=None, net_abuse_email=None) -> None:
        self.conn.execute(
            """
            UPDATE domains SET
                net_range       = COALESCE(net_range, ?),
                net_name        = COALESCE(net_name, ?),
                net_org         = COALESCE(net_org, ?),
                net_country     = COALESCE(net_country, ?),
                net_abuse_email = COALESCE(net_abuse_email, ?)
            WHERE domain = ?
            """,
            (net_range, net_name, net_org, net_country, net_abuse_email, domain),
        )

    # -- per-row stage flags --------------------------------------------
    def mark_row_done(self, domain: str, flag: str) -> None:
        if flag not in ROW_FLAGS:
            raise ValueError(f"unknown row flag: {flag}")
        self.conn.execute(f"UPDATE domains SET {flag} = 1 WHERE domain = ?", (domain,))

    def mark_geo_done(self, domain: str) -> None:
        self.mark_row_done(domain, "s_geo")

    def reset_flag(self, flag: str) -> None:
        """Clear a per-row stage flag for every row (used by --force)."""
        if flag not in ROW_FLAGS:
            raise ValueError(f"unknown row flag: {flag}")
        with self.batch() as conn:
            conn.execute(f"UPDATE domains SET {flag} = 0")

    # -- coarse stage status --------------------------------------------
    def mark_stage(self, stage: str, status: str) -> None:
        with self.batch() as conn:
            conn.execute(
                "INSERT INTO meta(stage, status) VALUES (?, ?) "
                "ON CONFLICT(stage) DO UPDATE SET status = excluded.status",
                (stage, status),
            )

    def stage_status(self, stage: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT status FROM meta WHERE stage = ?", (stage,)
        ).fetchone()
        return row[0] if row else None

    def stage_done(self, stage: str) -> bool:
        return self.stage_status(stage) == "done"
