import pytest

from domain_enrich.sources.zonefile import parse_zone, run_zone
from domain_enrich.store import Store


ZONE = """\
; CZDS-style flat zone
example.com. 86400 IN NS ns1.example.net.
example.com. 86400 IN NS ns2.example.net.
example.com. 3600 IN A 93.184.216.34
EXAMPLE.COM. 3600 IN AAAA 2606:2800:220:1:248:1893:25c8:1946
sub.example.com. 300 IN A 10.0.0.1
other.org. 86400 in ns a.ns.other.org.
"""


def test_parse_zone(tmp_path):
    z = tmp_path / "com.zone"
    z.write_text(ZONE)
    recs = parse_zone(str(z))
    assert set(recs["example.com"]["ns"]) == {"ns1.example.net", "ns2.example.net"}
    assert recs["example.com"]["a"] == ["93.184.216.34"]
    assert recs["example.com"]["aaaa"] == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert recs["sub.example.com"]["a"] == ["10.0.0.1"]
    assert recs["other.org"]["ns"] == ["a.ns.other.org"]


def test_run_zone_fills_dns(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("example.com", "example.com"), ("nope.com", "nope.com")])
    z = tmp_path / "com.zone"
    z.write_text(ZONE)
    matched = run_zone(store, [str(z)])
    assert matched == 1
    import json
    row = next(r for r in store.iter_rows(10) if r["domain"] == "example.com")
    assert json.loads(row["a"]) == ["93.184.216.34"]
    assert set(json.loads(row["ns"])) == {"ns1.example.net", "ns2.example.net"}
    assert row["s_zone"] == 1
    store.close()
