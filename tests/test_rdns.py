import gzip
import json

import pytest

from domain_enrich.sources.rdns import accumulate_rdns, run_rdns
from domain_enrich.store import Store


def test_accumulate_only_matches_ipset():
    records = [
        {"name": "1.2.3.4", "type": "ptr", "value": "host-a.example.net"},
        {"name": "1.2.3.4", "value": "alias.example.net"},          # type optional
        {"name": "9.9.9.9", "type": "ptr", "value": "other.net"},   # not in set
        {"name": "5.6.7.8", "type": "a", "value": "skip.net"},      # wrong type
    ]
    acc = accumulate_rdns(records, {"1.2.3.4", "5.6.7.8"})
    assert acc["1.2.3.4"] == {"host-a.example.net", "alias.example.net"}
    assert "9.9.9.9" not in acc
    assert "5.6.7.8" not in acc  # only non-ptr records -> nothing kept


def test_run_rdns_writes_ptr(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("a.com", "a.com"), ("b.com", "b.com")])
    store.update_dns("a.com", ips=["1.2.3.4"])
    store.update_dns("b.com", ips=["8.8.8.8"])  # no rdns record -> stays empty

    dump = tmp_path / "rdns.json.gz"
    with gzip.open(dump, "wt") as fh:
        fh.write(json.dumps({"name": "1.2.3.4", "type": "ptr", "value": "host.example.net"}) + "\n")
        fh.write(json.dumps({"name": "203.0.113.9", "type": "ptr", "value": "x.net"}) + "\n")

    matched = run_rdns(store, str(dump))
    assert matched == 1
    rows = {r["domain"]: r for r in store.iter_rows(10)}
    assert json.loads(rows["a.com"]["ptr"]) == ["host.example.net"]
    assert rows["a.com"]["s_rdns"] == 1
    assert rows["b.com"]["ptr"] is None
    assert rows["b.com"]["s_rdns"] == 1
    store.close()


def test_run_rdns_plain_jsonlines(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("a.com", "a.com")])
    store.update_dns("a.com", ips=["1.2.3.4"])
    dump = tmp_path / "rdns.jsonl"
    dump.write_text(json.dumps({"name": "1.2.3.4", "value": "plain.example.net"}) + "\n")
    matched = run_rdns(store, str(dump))
    assert matched == 1
    row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
    assert json.loads(row["ptr"]) == ["plain.example.net"]
    store.close()
