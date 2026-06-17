import json

import pytest

from domain_enrich.sources.peeringdb import parse_peeringdb, run_peeringdb
from domain_enrich.store import Store


SAMPLE = {"data": [
    {"asn": 15169, "name": "Google LLC", "info_type": "Content"},
    {"asn": 13335, "name": "Cloudflare", "info_type": "Content"},
]}


def test_parse_peeringdb(tmp_path):
    p = tmp_path / "net.json"
    p.write_text(json.dumps(SAMPLE))
    m = parse_peeringdb(str(p))
    assert m[15169] == {"name": "Google LLC", "info_type": "Content"}
    assert m[13335]["name"] == "Cloudflare"


def test_run_peeringdb_fills_asn_info(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("a.com", "a.com"), ("b.com", "b.com")])
    store.update_geo("a.com", asn=15169)          # has ASN, no org
    store.update_geo("b.com", asn=64500)          # ASN not in peeringdb
    p = tmp_path / "net.json"
    p.write_text(json.dumps(SAMPLE))

    matched = run_peeringdb(store, str(p))
    assert matched == 1
    rows = {r["domain"]: r for r in store.iter_rows(10)}
    assert rows["a.com"]["asn_org"] == "Google LLC"
    assert rows["a.com"]["asn_type"] == "Content"
    assert rows["a.com"]["s_peeringdb"] == 1
    assert rows["b.com"]["asn_org"] is None
