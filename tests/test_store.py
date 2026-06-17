import json

import pytest

from domain_enrich.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "work.db"))
    yield s
    s.close()


class TestAddDomains:
    def test_returns_count_of_new_rows(self, store):
        n = store.add_domains([("a.com", "A.com"), ("b.com", "b.com")])
        assert n == 2

    def test_insert_or_ignore_dedups(self, store):
        store.add_domains([("a.com", "A.com")])
        n = store.add_domains([("a.com", "a.com"), ("c.com", "c.com")])
        assert n == 1
        assert store.all_domains() == {"a.com", "c.com"}

    def test_all_domains_returns_set(self, store):
        store.add_domains([("a.com", "a.com"), ("b.com", "b.com")])
        assert store.all_domains() == {"a.com", "b.com"}


class TestDnsWriter:
    def test_update_dns_writes_fields(self, store):
        store.add_domains([("a.com", "a.com")])
        store.update_dns("a.com", a=["1.2.3.4"], ips=["1.2.3.4"], ns=["ns1.a.com"])
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        assert json.loads(row["a"]) == ["1.2.3.4"]
        assert json.loads(row["ips"]) == ["1.2.3.4"]

    def test_coalesce_does_not_overwrite_existing(self, store):
        store.add_domains([("a.com", "a.com")])
        store.update_dns("a.com", a=["1.1.1.1"], ips=["1.1.1.1"])
        # A weaker later writer must not clobber the richer existing value.
        store.update_dns("a.com", a=["9.9.9.9"], ips=["9.9.9.9"])
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        assert json.loads(row["a"]) == ["1.1.1.1"]

    def test_coalesce_fills_empty_fields(self, store):
        store.add_domains([("a.com", "a.com")])
        store.update_dns("a.com", a=["1.1.1.1"])
        store.update_dns("a.com", aaaa=["::1"])
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        assert json.loads(row["a"]) == ["1.1.1.1"]
        assert json.loads(row["aaaa"]) == ["::1"]


class TestGeoWriter:
    def test_update_geo_writes_fields(self, store):
        store.add_domains([("a.com", "a.com")])
        store.update_dns("a.com", ips=["1.2.3.4"])
        store.update_geo("a.com", geo_country="US", asn=15169, asn_org="Google")
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        assert row["geo_country"] == "US"
        assert row["asn"] == 15169
        assert row["asn_org"] == "Google"


class TestThreatWriter:
    def test_update_threat_writes_label_and_sources(self, store):
        store.add_domains([("a.com", "a.com")])
        store.update_threat("a.com", threat_label="phishing", threat_sources="urlhaus")
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        assert row["threat_label"] == "phishing"
        assert row["threat_sources"] == "urlhaus"

    def test_threat_label_not_downgraded(self, store):
        store.add_domains([("a.com", "a.com")])
        store.update_threat("a.com", threat_label="malware", threat_sources="brno")
        # Later weaker write must not overwrite an existing rich label.
        store.update_threat("a.com", threat_label="benign", threat_sources="x")
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        assert row["threat_label"] == "malware"


class TestTrancoWriter:
    def test_update_tranco_writes_rank(self, store):
        store.add_domains([("a.com", "a.com")])
        store.update_tranco("a.com", popularity_rank=42)
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        assert row["popularity_rank"] == 42


class TestRdapWriter:
    def test_update_rdap_writes_fields(self, store):
        store.add_domains([("a.com", "a.com")])
        store.update_rdap(
            "a.com",
            registrar="NameCheap, Inc.",
            created_date="2020-01-01T00:00:00Z",
            expires_date="2025-01-01T00:00:00Z",
            registrant_org="Privacy Inc.",
            domain_status="clientTransferProhibited",
            nameservers=["dns1.example.com", "dns2.example.com"],
        )
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        assert row["registrar"] == "NameCheap, Inc."
        assert row["created_date"] == "2020-01-01T00:00:00Z"
        assert row["registrant_org"] == "Privacy Inc."
        assert json.loads(row["nameservers"]) == ["dns1.example.com", "dns2.example.com"]

    def test_rdap_coalesce_does_not_overwrite(self, store):
        store.add_domains([("a.com", "a.com")])
        store.update_rdap("a.com", registrar="First Reg")
        store.update_rdap("a.com", registrar="Second Reg")
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        assert row["registrar"] == "First Reg"


class TestMigration:
    def test_reopen_old_db_adds_new_columns(self, tmp_path):
        import sqlite3
        path = str(tmp_path / "old.db")
        # Simulate a pre-existing DB without the newer columns.
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE domains (domain TEXT PRIMARY KEY, original TEXT, "
            "s_brno INTEGER DEFAULT 0, s_rapid7 INTEGER DEFAULT 0, "
            "s_geo INTEGER DEFAULT 0, s_threat INTEGER DEFAULT 0)"
        )
        conn.execute("INSERT INTO domains(domain, original) VALUES ('a.com','a.com')")
        conn.commit()
        conn.close()

        s = Store(path)  # must migrate without error
        s.update_tranco("a.com", popularity_rank=7)
        s.update_rdap("a.com", registrar="R")
        row = next(r for r in s.iter_rows(10) if r["domain"] == "a.com")
        assert row["popularity_rank"] == 7
        assert row["registrar"] == "R"
        assert row["s_tranco"] == 0 and row["s_rdap"] == 0
        s.close()


class TestStageState:
    def test_stage_done_false_then_true(self, store):
        assert store.stage_done("brno") is False
        store.mark_stage("brno", "done")
        assert store.stage_done("brno") is True

    def test_mark_stage_other_status_not_done(self, store):
        store.mark_stage("brno", "running")
        assert store.stage_done("brno") is False


class TestIterIps:
    def test_iter_ips_only_with_ips_and_geo_pending(self, store):
        store.add_domains([("a.com", "a.com"), ("b.com", "b.com"), ("c.com", "c.com")])
        store.update_dns("a.com", ips=["1.2.3.4"])
        store.update_dns("b.com", ips=["5.6.7.8"])
        # c.com has no ips -> excluded
        # mark a.com geo done -> excluded
        store.update_geo("a.com", geo_country="US")
        store.mark_geo_done("a.com")
        result = dict(store.iter_ips())
        assert "b.com" in result
        assert result["b.com"] == ["5.6.7.8"]
        assert "a.com" not in result
        assert "c.com" not in result


class TestResumability:
    def test_iter_rows_pending_skips_done(self, store):
        store.add_domains([("a.com", "a.com"), ("b.com", "b.com")])
        store.mark_row_done("a.com", "s_brno")
        pending = [r["domain"] for r in store.iter_rows_pending("s_brno", 10)]
        assert pending == ["b.com"]
