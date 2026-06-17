import pytest

from domain_enrich.sources.blocklists import (
    domain_from_token,
    parse_blocklist,
    build_bad_map,
    label_for_list,
)


class TestDomainFromToken:
    def test_plain_domain(self):
        assert domain_from_token("Evil.COM") == "evil.com"

    def test_url(self):
        assert domain_from_token("http://evil.com/path?x=1") == "evil.com"

    def test_ipv4_rejected(self):
        assert domain_from_token("0.0.0.0") is None
        assert domain_from_token("127.0.0.1") is None

    def test_junk_rejected(self):
        assert domain_from_token("online") is None
        assert domain_from_token("2023-01-01") is None


class TestParseHosts:
    def test_hosts_format(self, tmp_path):
        p = tmp_path / "hosts.txt"
        p.write_text(
            "# StevenBlack hosts\n"
            "0.0.0.0 ads.example.com\n"
            "127.0.0.1 tracker.bad.net\n"
            "0.0.0.0 0.0.0.0\n"
            "\n"
            "plain-in-hosts.org\n"
        )
        assert parse_blocklist(str(p)) == {
            "ads.example.com",
            "tracker.bad.net",
            "plain-in-hosts.org",
        }


class TestParseCsv:
    def test_urlhaus_like_csv(self, tmp_path):
        p = tmp_path / "urlhaus.csv"
        p.write_text(
            "# URLhaus dump\n"
            '"id","dateadded","url","url_status"\n'
            '"1","2023-01-01","http://evil.example.com/x.php","online"\n'
            '"2","2023-01-02","https://malware.test/","online"\n'
        )
        assert parse_blocklist(str(p)) == {"evil.example.com", "malware.test"}

    def test_phishtank_like_csv_ignores_reference_column(self, tmp_path):
        # The phish_detail_url column points back at phishtank.com and must
        # NOT be picked up as a bad domain.
        p = tmp_path / "phishtank.csv"
        p.write_text(
            "phish_id,url,phish_detail_url,submission_time\n"
            "123,http://phish.example.org/login,"
            "http://www.phishtank.com/phish_detail.php?phish_id=123,2023\n"
        )
        result = parse_blocklist(str(p))
        assert "phish.example.org" in result
        assert "phishtank.com" not in result


class TestParseCommentedHeaderCsv:
    def test_urlhaus_recent_format_with_commented_header(self, tmp_path):
        # URLhaus puts the column header inside the comment block and every row
        # carries a urlhaus_link pointing back at urlhaus.abuse.ch. We must
        # extract the malicious url column and NOT the feed's own infra domain.
        p = tmp_path / "urlhaus.csv"
        p.write_text(
            "################################################\n"
            "# abuse.ch URLhaus Database Dump                #\n"
            "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
            "#\n"
            '"1","2026-01-01","https://evil.example.com/x","online","",'
            '"malware_download","tag","https://urlhaus.abuse.ch/url/1/","rep"\n'
            '"2","2026-01-02","http://bad.test:8080/i","online","",'
            '"malware_download","tag","https://urlhaus.abuse.ch/url/2/","rep"\n'
        )
        result = parse_blocklist(str(p))
        assert "evil.example.com" in result
        assert "bad.test" in result
        assert "urlhaus.abuse.ch" not in result


class TestLabelForList:
    def test_phishtank_is_phishing(self):
        assert label_for_list("phishtank") == "phishing"

    def test_urlhaus_is_malware(self):
        assert label_for_list("urlhaus") == "malware"

    def test_threatfox_is_malware(self):
        assert label_for_list("threatfox_full") == "malware"

    def test_unknown_is_generic(self):
        assert label_for_list("stevenblack_hosts") == "blocklisted"


class TestParsePlain:
    def test_plain_list(self, tmp_path):
        p = tmp_path / "plain.txt"
        p.write_text(
            "# plain list\n"
            "plainbad1.com\n"
            "plainbad2.net\n"
            "not a domain\n"
        )
        assert parse_blocklist(str(p)) == {"plainbad1.com", "plainbad2.net"}


class TestBuildBadMap:
    def test_maps_domain_to_list_names(self, tmp_path):
        a = tmp_path / "urlhaus.txt"
        a.write_text("evil.com\nshared.com\n")
        b = tmp_path / "phishtank.txt"
        b.write_text("shared.com\nphish.net\n")
        m = build_bad_map([str(a), str(b)])
        assert m["evil.com"] == {"urlhaus"}
        assert m["phish.net"] == {"phishtank"}
        assert m["shared.com"] == {"urlhaus", "phishtank"}
