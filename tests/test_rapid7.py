import gzip
import json

import pytest

from domain_enrich.sources.rapid7 import accumulate_fdns, run_rapid7
from domain_enrich.store import Store


def test_accumulate_only_matches_working_set():
    records = [
        {"name": "a.com", "type": "a", "value": "1.1.1.1"},
        {"name": "a.com", "type": "a", "value": "1.1.1.2"},
        {"name": "a.com", "type": "aaaa", "value": "::1"},
        {"name": "other.com", "type": "a", "value": "9.9.9.9"},
        {"name": "b.com", "type": "cname", "value": "x.com"},  # ignored type
    ]
    acc = accumulate_fdns(records, {"a.com", "b.com"})
    assert acc["a.com"]["a"] == {"1.1.1.1", "1.1.1.2"}
    assert acc["a.com"]["aaaa"] == {"::1"}
    assert "other.com" not in acc
    # b.com had only a cname -> no a/aaaa accumulated
    assert "b.com" not in acc or not acc["b.com"]["a"]


def test_run_rapid7_writes_to_store(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("match.com", "match.com"), ("nohit.com", "nohit.com")])

    fdns = tmp_path / "fdns.json.gz"
    with gzip.open(fdns, "wt") as fh:
        fh.write(json.dumps({"name": "match.com", "type": "a", "value": "1.2.3.4"}) + "\n")
        fh.write(json.dumps({"name": "match.com", "type": "aaaa", "value": "::1"}) + "\n")
        fh.write(json.dumps({"name": "unrelated.com", "type": "a", "value": "8.8.8.8"}) + "\n")

    matched = run_rapid7(store, str(fdns))
    assert matched == 1

    row = next(r for r in store.iter_rows(10) if r["domain"] == "match.com")
    assert json.loads(row["a"]) == ["1.2.3.4"]
    assert json.loads(row["ips"]) == ["1.2.3.4", "::1"]
    # stage flag set for resumability
    assert row["s_rapid7"] == 1
    store.close()
