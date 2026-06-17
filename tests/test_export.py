import csv
import json

import pandas as pd
import pytest

from domain_enrich.export import flatten_row, available_fields, export
from domain_enrich.store import Store


def test_flatten_expands_lists_and_tls():
    row = {
        "domain": "a.com",
        "original": "A.com",
        "a": json.dumps(["1.2.3.4", "5.6.7.8"]),
        "ips": json.dumps(["1.2.3.4", "5.6.7.8"]),
        "tls": json.dumps({"cipher": "AESGCM", "protocol": "TLSv1.3",
                            "sans": ["x.a.com", "y.a.com"]}),
        "geo_country": "US",
        "asn_org": "Google",
        "threat_label": "benign",
    }
    flat = flatten_row(row)
    assert flat["a"] == "1.2.3.4;5.6.7.8"
    assert flat["ips"] == "1.2.3.4;5.6.7.8"
    assert flat["tls_cipher"] == "AESGCM"
    assert flat["tls_protocol"] == "TLSv1.3"
    assert flat["tls_sans"] == "x.a.com;y.a.com"
    assert flat["geo_country"] == "US"
    assert flat["asn_org"] == "Google"


def test_available_fields_includes_flat_names():
    fields = available_fields()
    for f in ("domain", "ips", "geo_country", "asn_org", "threat_label", "tls_protocol"):
        assert f in fields


def _seed(store):
    store.add_domains([("a.com", "a.com")])
    store.update_dns("a.com", a=["1.2.3.4"], ips=["1.2.3.4"])
    store.update_geo("a.com", geo_country="US", asn_org="Google")
    store.update_threat("a.com", threat_label="phishing", threat_sources="urlhaus")


def test_export_csv(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    _seed(store)
    out = tmp_path / "out.csv"
    export(store, str(out), fields=["domain", "ips", "geo_country", "threat_label"],
           fmt="csv")
    store.close()
    with open(out) as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["domain"] == "a.com"
    assert rows[0]["ips"] == "1.2.3.4"
    assert rows[0]["geo_country"] == "US"
    assert rows[0]["threat_label"] == "phishing"


def test_export_parquet(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    _seed(store)
    out = tmp_path / "out.parquet"
    export(store, str(out), fields=None, fmt="parquet")
    store.close()
    df = pd.read_parquet(out)
    assert df.iloc[0]["domain"] == "a.com"
    assert df.iloc[0]["asn_org"] == "Google"
