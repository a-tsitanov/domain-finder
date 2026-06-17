"""click CLI: a full ``run`` plus per-stage subcommands for debugging.

Every subcommand operates over the same ``--db`` and is resumable, so you can
run stages one at a time, kill a stage mid-flight, and continue later.
"""

from __future__ import annotations

from typing import Optional, Tuple

import click

from . import pipeline
from .export import available_fields
from .store import Store


def _split_fields(value: Optional[str]):
    if not value:
        return None
    return [f.strip() for f in value.split(",") if f.strip()]


# Shared options ---------------------------------------------------------
_db_opt = click.option("--db", required=True, type=click.Path(),
                       help="Path to the SQLite working database.")


@click.group()
@click.version_option(package_name="domain-enrich")
def cli() -> None:
    """Offline, resumable domain enrichment."""


@cli.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True),
              help="Input file: one domain per line.")
@_db_opt
@click.option("--output", required=True, type=click.Path(),
              help="Output table path.")
@click.option("--brno-dir", multiple=True, envvar="DE_BRNO_DIR", type=click.Path(),
              help="Brno dataset file/dir/glob (repeatable). Env: DE_BRNO_DIR")
@click.option("--rapid7-fdns", envvar="DE_RAPID7_FDNS", type=click.Path(),
              help="Rapid7 FDNS .json.gz. Env: DE_RAPID7_FDNS")
@click.option("--maxmind-city", envvar="DE_MAXMIND_CITY", type=click.Path(),
              help="GeoLite2-City.mmdb. Env: DE_MAXMIND_CITY")
@click.option("--maxmind-asn", envvar="DE_MAXMIND_ASN", type=click.Path(),
              help="GeoLite2-ASN.mmdb. Env: DE_MAXMIND_ASN")
@click.option("--blocklist", multiple=True, envvar="DE_BLOCKLIST", type=click.Path(),
              help="Blocklist file (repeatable). Env: DE_BLOCKLIST (':'-separated)")
@click.option("--tranco", envvar="DE_TRANCO", type=click.Path(),
              help="Tranco rank,domain CSV. Env: DE_TRANCO")
@click.option("--rir-dump", multiple=True, envvar="DE_RIR_DUMP", type=click.Path(),
              help="RIR RPSL whois dump for network whois (repeatable). Env: DE_RIR_DUMP")
@click.option("--rdns-dump", envvar="DE_RDNS_DUMP", type=click.Path(),
              help="Offline reverse-DNS (PTR) dump, JSON-lines (.gz ok). Env: DE_RDNS_DUMP")
@click.option("--rdap-dump", multiple=True, envvar="DE_RDAP_DUMP", type=click.Path(),
              help="Standalone offline RDAP dump (repeatable). Env: DE_RDAP_DUMP")
@click.option("--zone", multiple=True, envvar="DE_ZONE", type=click.Path(),
              help="DNS zone files (CZDS/BIND) for forward DNS. Env: DE_ZONE")
@click.option("--ipthreat", multiple=True, envvar="DE_IPTHREAT", type=click.Path(),
              help="IP/CIDR threat feeds (Feodo/DROP/SSLBL). Env: DE_IPTHREAT")
@click.option("--peeringdb", envvar="DE_PEERINGDB", type=click.Path(),
              help="PeeringDB net JSON dump (ASN -> org/type). Env: DE_PEERINGDB")
@click.option("--ct-dump", multiple=True, envvar="DE_CT_DUMP", type=click.Path(),
              help="Certificate Transparency dump (SANs/TLS). Env: DE_CT_DUMP")
@click.option("--fields", default=None, help="Comma-separated output fields.")
@click.option("--format", "fmt", type=click.Choice(["parquet", "csv", "both"]),
              default="parquet", show_default=True)
@click.option("--force", multiple=True,
              type=click.Choice(["normalize", "brno", "rapid7", "geo", "threat",
                                 "tranco", "netwhois", "rdns", "rdap", "zone",
                                 "ipthreat", "peeringdb", "ct"]),
              help="Re-run a stage from scratch (repeatable).")
@click.option("--resume", is_flag=True, default=False,
              help="No-op marker; resuming is always on by default.")
def run(input_path, db, output, brno_dir, rapid7_fdns, maxmind_city,
        maxmind_asn, blocklist, tranco, rir_dump, rdns_dump, rdap_dump, zone,
        ipthreat, peeringdb, ct_dump, fields, fmt, force, resume):
    """Run the full pipeline end to end (fully offline)."""
    pipeline.run(
        input_path=input_path,
        db=db,
        output=output,
        brno_dir=list(brno_dir),
        rapid7_fdns=rapid7_fdns,
        maxmind_city=maxmind_city,
        maxmind_asn=maxmind_asn,
        blocklist=list(blocklist),
        tranco=tranco,
        rir_dump=list(rir_dump),
        rdns_dump=rdns_dump,
        rdap_dump=list(rdap_dump),
        zone=list(zone),
        ipthreat=list(ipthreat),
        peeringdb=peeringdb,
        ct_dump=list(ct_dump),
        fields=_split_fields(fields),
        fmt=fmt,
        force=set(force),
    )


@cli.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@_db_opt
def normalize(input_path, db):
    """Read + normalize the input into the store."""
    with Store(db) as store:
        pipeline.stage_normalize(store, input_path)


@cli.command()
@click.option("--brno-dir", multiple=True, required=True, type=click.Path())
@_db_opt
@click.option("--force", is_flag=True, default=False)
def brno(brno_dir, db, force):
    """Join against the Brno dataset."""
    with Store(db) as store:
        pipeline.stage_brno(store, list(brno_dir), {"brno"} if force else set())


@cli.command()
@click.option("--rapid7-fdns", required=True, type=click.Path(exists=True))
@_db_opt
@click.option("--force", is_flag=True, default=False)
def rapid7(rapid7_fdns, db, force):
    """Join against the Rapid7 FDNS dump."""
    with Store(db) as store:
        pipeline.stage_rapid7(store, rapid7_fdns, {"rapid7"} if force else set())


@cli.command()
@click.option("--maxmind-city", type=click.Path(exists=True))
@click.option("--maxmind-asn", type=click.Path(exists=True))
@_db_opt
@click.option("--force", is_flag=True, default=False)
def geo(maxmind_city, maxmind_asn, db, force):
    """Resolve GeoIP + ASN from MaxMind."""
    with Store(db) as store:
        pipeline.stage_geo(store, maxmind_city, maxmind_asn,
                           {"geo"} if force else set())


@cli.command()
@click.option("--blocklist", multiple=True, required=True, type=click.Path())
@_db_opt
@click.option("--force", is_flag=True, default=False)
def threat(blocklist, db, force):
    """Apply blocklist threat labels."""
    with Store(db) as store:
        pipeline.stage_threat(store, list(blocklist),
                              {"threat"} if force else set())


@cli.command()
@click.option("--tranco", required=True, type=click.Path(exists=True))
@_db_opt
@click.option("--force", is_flag=True, default=False)
def tranco(tranco, db, force):
    """Stamp Tranco popularity rank."""
    with Store(db) as store:
        pipeline.stage_tranco(store, tranco, {"tranco"} if force else set())


@cli.command()
@click.option("--rir-dump", multiple=True, required=True, type=click.Path())
@_db_opt
@click.option("--force", is_flag=True, default=False)
def netwhois(rir_dump, db, force):
    """Resolve network whois from offline RIR dumps."""
    with Store(db) as store:
        pipeline.stage_netwhois(store, list(rir_dump),
                                {"netwhois"} if force else set())


@cli.command()
@click.option("--rdns-dump", required=True, type=click.Path(exists=True))
@_db_opt
@click.option("--force", is_flag=True, default=False)
def rdns(rdns_dump, db, force):
    """Fill reverse-DNS (PTR) from an offline RDNS dump."""
    with Store(db) as store:
        pipeline.stage_rdns(store, rdns_dump, {"rdns"} if force else set())


@cli.command()
@click.option("--rdap-dump", multiple=True, required=True, type=click.Path())
@_db_opt
@click.option("--force", is_flag=True, default=False)
def rdap(rdap_dump, db, force):
    """Apply a standalone offline RDAP dump (domain whois)."""
    with Store(db) as store:
        pipeline.stage_rdap(store, list(rdap_dump), {"rdap"} if force else set())


@cli.command()
@click.option("--zone", multiple=True, required=True, type=click.Path())
@_db_opt
@click.option("--force", is_flag=True, default=False)
def zone(zone, db, force):
    """Fill forward DNS (NS/A/AAAA) from offline zone files."""
    with Store(db) as store:
        pipeline.stage_zone(store, list(zone), {"zone"} if force else set())


@cli.command()
@click.option("--ipthreat", multiple=True, required=True, type=click.Path())
@_db_opt
@click.option("--force", is_flag=True, default=False)
def ipthreat(ipthreat, db, force):
    """Flag domains by IP/CIDR threat feeds (Feodo/DROP/SSLBL)."""
    with Store(db) as store:
        pipeline.stage_ipthreat(store, list(ipthreat), {"ipthreat"} if force else set())


@cli.command()
@click.option("--peeringdb", required=True, type=click.Path(exists=True))
@_db_opt
@click.option("--force", is_flag=True, default=False)
def peeringdb(peeringdb, db, force):
    """Fill ASN org/type from a PeeringDB dump."""
    with Store(db) as store:
        pipeline.stage_peeringdb(store, peeringdb, {"peeringdb"} if force else set())


@cli.command()
@click.option("--ct-dump", multiple=True, required=True, type=click.Path())
@_db_opt
@click.option("--force", is_flag=True, default=False)
def ct(ct_dump, db, force):
    """Fill SANs/TLS from an offline Certificate Transparency dump."""
    with Store(db) as store:
        pipeline.stage_ct(store, list(ct_dump), {"ct"} if force else set())


@cli.command()
@_db_opt
@click.option("--output", required=True, type=click.Path())
@click.option("--fields", default=None, help="Comma-separated output fields.")
@click.option("--format", "fmt", type=click.Choice(["parquet", "csv", "both"]),
              default="parquet", show_default=True)
def export(db, output, fields, fmt):
    """Export the flat table to parquet/CSV."""
    with Store(db) as store:
        pipeline.stage_export(store, output, _split_fields(fields), fmt)


_DOSSIER_GROUPS = [
    ("Address lookup / DNS records",
     ["domain", "a", "aaaa", "ns", "mx", "txt", "cname", "soa", "ptr", "ips"]),
    ("Domain Whois",
     ["registrar", "registrar_ianaid", "whois_server", "created_date",
      "updated_date", "expires_date", "registrant_org", "registrant_country",
      "abuse_email", "domain_status", "dnssec", "nameservers"]),
    ("Network Whois",
     ["net_range", "net_name", "net_org", "net_country", "net_abuse_email"]),
    ("GeoIP + ASN",
     ["geo_country", "geo_city", "geo_lat", "geo_lon", "asn", "asn_org",
      "asn_network", "asn_type"]),
    ("TLS", ["tls_cipher", "tls_protocol", "tls_sans"]),
    ("Popularity / Threat",
     ["popularity_rank", "threat_label", "threat_sources"]),
]


def _expand_paths(value):
    """A path may be a file or a directory; a directory expands to its files."""
    import glob
    import os
    out = []
    for p in (value or ()):
        if p and os.path.isdir(p):
            out.extend(sorted(f for f in glob.glob(os.path.join(p, "*"))
                              if os.path.isfile(f)))
        elif p:
            out.append(p)
    return out


@cli.command()
@click.argument("domain")
@click.option("--brno-dir", multiple=True, envvar="DE_BRNO_DIR", type=click.Path())
@click.option("--rapid7-fdns", envvar="DE_RAPID7_FDNS", type=click.Path())
@click.option("--maxmind-city", envvar="DE_MAXMIND_CITY", type=click.Path())
@click.option("--maxmind-asn", envvar="DE_MAXMIND_ASN", type=click.Path())
@click.option("--rir-dump", multiple=True, envvar="DE_RIR_DUMP", type=click.Path())
@click.option("--rdns-dump", envvar="DE_RDNS_DUMP", type=click.Path())
@click.option("--blocklist", multiple=True, envvar="DE_BLOCKLIST", type=click.Path())
@click.option("--tranco", envvar="DE_TRANCO", type=click.Path())
@click.option("--rdap-dump", multiple=True, envvar="DE_RDAP_DUMP", type=click.Path())
@click.option("--zone", multiple=True, envvar="DE_ZONE", type=click.Path())
@click.option("--ipthreat", multiple=True, envvar="DE_IPTHREAT", type=click.Path())
@click.option("--peeringdb", envvar="DE_PEERINGDB", type=click.Path())
@click.option("--ct-dump", multiple=True, envvar="DE_CT_DUMP", type=click.Path())
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON object.")
@click.option("--compact", is_flag=True, help="Hide empty fields/sections.")
def lookup(domain, brno_dir, rapid7_fdns, maxmind_city, maxmind_asn, rir_dump,
           rdns_dump, blocklist, tranco, rdap_dump, zone, ipthreat, peeringdb,
           ct_dump, as_json, compact):
    """Enrich a SINGLE domain and print a Domain-Dossier-style report.

    Source paths default to the DE_* environment variables, so inside the
    runner container you only type:  domain-enrich lookup example.com
    """
    import json as _json
    row = pipeline.lookup_domain(
        domain,
        brno_dir=_expand_paths(brno_dir),
        rapid7_fdns=rapid7_fdns,
        maxmind_city=maxmind_city,
        maxmind_asn=maxmind_asn,
        rir_dump=_expand_paths(rir_dump),
        rdns_dump=rdns_dump,
        blocklist=_expand_paths(blocklist),
        tranco=tranco,
        rdap_dump=_expand_paths(rdap_dump),
        zone=_expand_paths(zone),
        ipthreat=_expand_paths(ipthreat),
        peeringdb=peeringdb,
        ct_dump=_expand_paths(ct_dump),
    )
    if row is None:
        raise click.ClickException(f"could not enrich {domain!r}")
    if as_json:
        click.echo(_json.dumps(row, ensure_ascii=False, indent=2))
        return
    # Default: full dossier — every section and field, empties shown as "·"
    # (like centralops). --compact drops empty fields and empty sections.
    for title, keys in _DOSSIER_GROUPS:
        rows = [(k, row.get(k)) for k in keys]
        if compact:
            rows = [(k, v) for k, v in rows if v not in (None, "")]
            if not rows:
                continue
        click.echo(f"\n=== {title} ===")
        for k, v in rows:
            click.echo(f"  {k:18}: {'·' if v in (None, '') else v}")


@cli.command(name="fields")
def list_fields():
    """List available export fields."""
    for f in available_fields():
        click.echo(f)


if __name__ == "__main__":
    cli()
