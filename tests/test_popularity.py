import pytest

from domain_enrich.sources.tranco import parse_popularity, run_popularity
from domain_enrich.store import Store


def test_parses_rank_comma_domain(tmp_path):  # Tranco / Umbrella
    p = tmp_path / "tranco.csv"
    p.write_text("1,google.com\n2,facebook.com\n")
    assert parse_popularity(str(p)) == {"google.com": 1, "facebook.com": 2}


def test_parses_majestic_header(tmp_path):
    # GlobalRank,TldRank,Domain,...
    p = tmp_path / "majestic_million.csv"
    p.write_text("GlobalRank,TldRank,Domain,TLD\n1,1,google.com,com\n3,2,facebook.com,com\n")
    m = parse_popularity(str(p))
    assert m["google.com"] == 1
    assert m["facebook.com"] == 3


def test_parses_domcop_header(tmp_path):
    # Rank,Domain,Open Page Rank
    p = tmp_path / "domcop_top10m.csv"
    p.write_text('"Rank","Domain","Open Page Rank"\n"1","google.com","10.00"\n')
    assert parse_popularity(str(p)) == {"google.com": 1}


def test_ensemble_keeps_best_rank(tmp_path):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("a.com", "a.com")])
    f1 = tmp_path / "tranco.csv"; f1.write_text("500,a.com\n")
    f2 = tmp_path / "umbrella.csv"; f2.write_text("42,a.com\n")
    matched = run_popularity(store, [str(f1), str(f2)])
    assert matched == 1
    row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
    assert row["popularity_rank"] == 42   # best (smallest) across lists
    store.close()
