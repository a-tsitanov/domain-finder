import pytest

from domain_enrich.sources.ipthreat import IpThreat, run_ipthreat
from domain_enrich.store import Store


def test_matches_exact_ip_and_cidr(tmp_path):
    feodo = tmp_path / "feodo_ipblocklist.txt"
    feodo.write_text("# Feodo Tracker\n1.2.3.4\n5.6.7.8\n")
    drop = tmp_path / "drop.txt"
    drop.write_text("; Spamhaus DROP\n10.10.0.0/16 ; SBL123\n203.0.113.0/24 ; SBL456\n")

    m = IpThreat()
    m.add(str(feodo))
    m.add(str(drop))
    assert m.match("1.2.3.4") == {"feodo_ipblocklist"}
    assert m.match("10.10.5.9") == {"drop"}          # inside CIDR
    assert m.match("9.9.9.9") == set()               # no match
    assert m.match("not-an-ip") == set()             # safe


def test_ipv6_version_safe(tmp_path):
    drop = tmp_path / "drop.txt"
    drop.write_text("2001:db8::/32\n")
    m = IpThreat()
    m.add(str(drop))
    assert m.match("2001:db8::1") == {"drop"}
    assert m.match("1.2.3.4") == set()               # v4 vs v6 must not crash


def test_run_ipthreat_flags_domain(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("bad.com", "bad.com"), ("ok.com", "ok.com")])
    store.update_dns("bad.com", ips=["1.2.3.4"])
    store.update_dns("ok.com", ips=["8.8.8.8"])
    feodo = tmp_path / "feodo.txt"
    feodo.write_text("1.2.3.4\n")

    matched = run_ipthreat(store, [str(feodo)])
    assert matched == 1
    rows = {r["domain"]: r for r in store.iter_rows(10)}
    assert rows["bad.com"]["threat_label"] == "malware"   # feodo -> malware
    assert rows["bad.com"]["threat_sources"] == "feodo"
    assert rows["ok.com"]["threat_label"] is None
    assert rows["bad.com"]["s_ipthreat"] == 1
    store.close()
