"""MaxMind GeoLite2 City + ASN adapter (fully offline).

Resolves each domain's IPs against the local ``.mmdb`` databases and writes
country/city/coordinates plus ASN/org/network. The first IP that resolves wins
(domains usually share one network); lookups are O(1) against the mmdb tree.
"""

from __future__ import annotations

from typing import Optional


def lookup_ip(city_reader, asn_reader, ip: str) -> dict:
    """Look one IP up in the City and ASN readers. Missing data is omitted."""
    out: dict = {}
    if city_reader is not None:
        try:
            c = city_reader.city(ip)
            if c.country.iso_code:
                out["geo_country"] = c.country.iso_code
            if c.city.name:
                out["geo_city"] = c.city.name
            if c.location.latitude is not None:
                out["geo_lat"] = c.location.latitude
            if c.location.longitude is not None:
                out["geo_lon"] = c.location.longitude
        except Exception:
            pass
    if asn_reader is not None:
        try:
            a = asn_reader.asn(ip)
            if a.autonomous_system_number is not None:
                out["asn"] = a.autonomous_system_number
            if a.autonomous_system_organization:
                out["asn_org"] = a.autonomous_system_organization
            if a.network is not None:
                out["asn_network"] = str(a.network)
        except Exception:
            pass
    return out


def run_maxmind(store, city_path: Optional[str], asn_path: Optional[str],
                batch_size: int = 5000, progress=None) -> int:
    """Resolve geo/ASN for every domain that has IPs and pending geo.

    Returns the number of domains enriched. Readers are imported lazily and
    always closed.
    """
    import geoip2.database

    city_reader = geoip2.database.Reader(city_path) if city_path else None
    asn_reader = geoip2.database.Reader(asn_path) if asn_path else None

    enriched = 0
    try:
        # Materialize the work list first: writing while iterating the same
        # cursor (and flipping s_geo) would disturb the open SELECT.
        work = list(store.iter_ips(batch_size))
        with store.batch():
            for domain, ips in work:
                data = {}
                for ip in ips:
                    found = lookup_ip(city_reader, asn_reader, ip)
                    if found:
                        data = found
                        break
                if data:
                    store.update_geo(domain, **data)
                    enriched += 1
                store.mark_geo_done(domain)
                if progress is not None:
                    progress.update(1)
    finally:
        if city_reader is not None:
            city_reader.close()
        if asn_reader is not None:
            asn_reader.close()
    return enriched
