import json

import pytest

from domain_enrich.sources.ct import parse_ct_record, run_ct
from domain_enrich.store import Store


def test_parse_ct_record_crtsh_style():
    rec = {
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com\napi.example.com",
    }
    domain, sans = parse_ct_record(rec)
    assert domain == "example.com"
    assert set(sans) == {"example.com", "www.example.com", "api.example.com"}


def test_run_ct_fills_san(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("example.com", "example.com")])
    dump = tmp_path / "ct.jsonl"
    dump.write_text(
        json.dumps({"common_name": "example.com",
                    "name_value": "example.com\nwww.example.com"}) + "\n"
        + json.dumps({"common_name": "other.com", "name_value": "other.com"}) + "\n"
    )
    matched = run_ct(store, [str(dump)])
    assert matched == 1
    row = next(r for r in store.iter_rows(10) if r["domain"] == "example.com")
    assert set(json.loads(row["san"])) == {"example.com", "www.example.com"}
    assert row["s_ct"] == 1
    store.close()
