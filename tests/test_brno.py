import pytest

from domain_enrich.sources.brno import (
    unwrap_ejson,
    label_from_filename,
    collect_files,
    lift_record,
)


class TestUnwrapEjson:
    def test_date_scalar(self):
        assert unwrap_ejson({"$date": "2023-01-01T00:00:00Z"}) == "2023-01-01T00:00:00Z"

    def test_number_long(self):
        assert unwrap_ejson({"$numberLong": "123"}) == 123

    def test_number_int(self):
        assert unwrap_ejson({"$numberInt": "5"}) == 5

    def test_number_double(self):
        assert unwrap_ejson({"$numberDouble": "1.5"}) == 1.5

    def test_oid(self):
        assert unwrap_ejson({"$oid": "deadbeef"}) == "deadbeef"

    def test_nested_structures(self):
        doc = {"a": {"$numberInt": "1"}, "b": [{"$numberLong": "2"}, "x"]}
        assert unwrap_ejson(doc) == {"a": 1, "b": [2, "x"]}

    def test_plain_passthrough(self):
        assert unwrap_ejson("hello") == "hello"
        assert unwrap_ejson(42) == 42

    def test_date_with_numberlong(self):
        assert unwrap_ejson({"$date": {"$numberLong": "1672531200000"}}) == 1672531200000

    def test_decimal_converted(self):
        # ijson parses JSON numbers as Decimal; these must become plain numbers
        # so the result is JSON-serializable downstream.
        from decimal import Decimal
        import json
        out = unwrap_ejson({"average_rtt": Decimal("0.5"), "hops": Decimal("12")})
        assert out == {"average_rtt": 0.5, "hops": 12}
        assert isinstance(out["hops"], int)
        json.dumps(out)  # must not raise


class TestLabelFromFilename:
    def test_benign_umbrella(self):
        assert label_from_filename("benign_umbrella_2023.json") == "benign"

    def test_benign_cesnet(self):
        assert label_from_filename("benign_cesnet.json") == "benign"

    def test_phishing(self):
        assert label_from_filename("phishing_2023.json") == "phishing"

    def test_malware(self):
        assert label_from_filename("malware_part1.json") == "malware"

    def test_unknown(self):
        assert label_from_filename("random.json") is None


class TestCollectFiles:
    def test_excludes_schema_and_expands_dir(self, tmp_path):
        (tmp_path / "phishing.json").write_text("[]")
        (tmp_path / "benign_umbrella.json").write_text("[]")
        (tmp_path / "schema.json").write_text("{}")
        files = collect_files([str(tmp_path)])
        names = {f.split("/")[-1] for f in files}
        assert names == {"phishing.json", "benign_umbrella.json"}

    def test_glob_pattern(self, tmp_path):
        (tmp_path / "malware_a.json").write_text("[]")
        (tmp_path / "malware_b.json").write_text("[]")
        files = collect_files([str(tmp_path / "malware_*.json")])
        assert len(files) == 2


class TestLiftRecord:
    def test_lifts_dns_tls_rdap_ip(self):
        doc = {
            "domain_name": "Example.com",
            "dns": {
                "A": [{"value": "1.2.3.4"}],
                "AAAA": [{"value": "::1"}],
                "NS": [{"value": "ns1.example.com"}],
                "MX": [{"value": "mail.example.com", "priority": {"$numberInt": "10"}}],
                "TXT": [{"value": "v=spf1 -all"}],
                "CNAME": ["alias.example.net"],
                "SOA": {"server": "ns1.example.com", "serial": {"$numberLong": "42"}},
            },
            "tls": {"cipher": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3"},
            "rdap": {"handle": "EX"},
            "ip_data": [{"ip": "1.2.3.4"}],
        }
        out = lift_record(doc)
        assert out["domain"] == "example.com"
        assert out["a"] == ["1.2.3.4"]
        assert out["aaaa"] == ["::1"]
        assert out["ns"] == ["ns1.example.com"]
        assert out["mx"] == ["mail.example.com"]
        assert sorted(out["ips"]) == ["1.2.3.4", "::1"]
        assert out["txt"] == ["v=spf1 -all"]
        assert out["cname"] == ["alias.example.net"]
        assert '"serial": 42' in out["soa"]
        assert out["tls"]["protocol"] == "TLSv1.3"
        assert out["rdap"]["handle"] == "EX"

    def test_plain_string_records(self):
        doc = {"domain_name": "a.com", "dns": {"A": ["9.9.9.9"]}}
        out = lift_record(doc)
        assert out["a"] == ["9.9.9.9"]
        assert out["ips"] == ["9.9.9.9"]

    def test_ptr_lifted_from_ip_data(self):
        doc = {
            "domain_name": "a.com",
            "dns": {"A": [{"value": "1.2.3.4"}]},
            "ip_data": [{"ip": "1.2.3.4", "ptr": "host.example.net"}],
        }
        out = lift_record(doc)
        assert out["ptr"] == ["host.example.net"]

    def test_missing_domain_returns_none(self):
        assert lift_record({"dns": {}}) is None


class TestTruncatedDump:
    def test_truncated_json_array_processed_partially(self, tmp_path):
        from domain_enrich.sources.brno import run_brno
        from domain_enrich.store import Store
        # A valid first record, then a truncated second one (partial download).
        text = '[{"domain_name":"a.com","dns":{"A":[{"value":"1.1.1.1"}]}},{"domain_name":"b.co'
        p = tmp_path / "benign_umbrella.json"
        p.write_text(text)
        store = Store(str(tmp_path / "w.db"))
        store.add_domains([("a.com", "a.com"), ("b.com", "b.com")])
        matched = run_brno(store, [str(p)])  # must NOT raise
        assert matched == 1  # only the complete record
        row = next(r for r in store.iter_rows(10) if r["domain"] == "a.com")
        import json as _j
        assert _j.loads(row["a"]) == ["1.1.1.1"]
        store.close()
