import pytest

from domain_enrich.sources.tranco import parse_tranco, run_tranco
from domain_enrich.store import Store


def test_parse_tranco_rank_domain(tmp_path):
    p = tmp_path / "tranco.csv"
    p.write_text("1,google.com\n2,facebook.com\n3,YouTube.com\n")
    m = parse_tranco(str(p))
    assert m["google.com"] == 1
    assert m["facebook.com"] == 2
    assert m["youtube.com"] == 3  # normalized lowercase


def test_parse_tranco_with_header(tmp_path):
    p = tmp_path / "tranco.csv"
    p.write_text("rank,domain\n1,google.com\n2,example.com\n")
    m = parse_tranco(str(p))
    assert m["google.com"] == 1
    assert "rank" not in m


def test_run_tranco_writes_rank(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("google.com", "google.com"), ("unranked.com", "unranked.com")])
    p = tmp_path / "tranco.csv"
    p.write_text("1,google.com\n5,other.com\n")
    matched = run_tranco(store, str(p))
    assert matched == 1
    rows = {r["domain"]: r for r in store.iter_rows(10)}
    assert rows["google.com"]["popularity_rank"] == 1
    assert rows["unranked.com"]["popularity_rank"] is None
    assert rows["google.com"]["s_tranco"] == 1
    store.close()
