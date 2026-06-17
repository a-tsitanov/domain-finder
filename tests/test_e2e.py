import gzip
import json

import pandas as pd
import pytest

from domain_enrich import pipeline
from domain_enrich.store import Store


@pytest.fixture
def fixtures(tmp_path):
    # --- input: 6 domains, mixed casing / URL wrappers ------------------
    inp = tmp_path / "domains.txt"
    inp.write_text(
        "Example.com\n"
        "http://evil.com/login\n"
        "malware.test\n"
        "onlyfdns.com\n"
        "onlyblock.com\n"
        "nodata.com\n"
    )

    # --- brno fixtures (label derived from file name) -------------------
    brno_dir = tmp_path / "brno"
    brno_dir.mkdir()
    (brno_dir / "benign_umbrella.json").write_text(json.dumps([
        {"domain_name": "example.com",
         "dns": {"A": [{"value": "93.184.216.34"}],
                 "NS": [{"value": "a.iana-servers.net"}]},
         "tls": {"cipher": "AESGCM", "protocol": "TLSv1.3"}},
    ]))
    (brno_dir / "phishing.json").write_text(json.dumps([
        {"domain_name": "evil.com", "dns": {"A": [{"value": "6.6.6.6"}]}},
    ]))
    (brno_dir / "malware.json").write_text(json.dumps([
        {"domain_name": "malware.test", "dns": {"A": [{"value": "7.7.7.7"}]}},
    ]))
    (brno_dir / "schema.json").write_text("{}")  # must be ignored

    # --- rapid7 FDNS: onlyfdns.com + a weaker example.com A -------------
    fdns = tmp_path / "fdns.json.gz"
    with gzip.open(fdns, "wt") as fh:
        fh.write(json.dumps({"name": "onlyfdns.com", "type": "a", "value": "8.8.8.8"}) + "\n")
        # example.com already has an A from Brno -> must NOT be overwritten.
        fh.write(json.dumps({"name": "example.com", "type": "a", "value": "1.1.1.1"}) + "\n")

    # --- blocklist: onlyblock.com + evil.com (already phishing) ---------
    block = tmp_path / "urlhaus.txt"
    block.write_text("# list\nonlyblock.com\nevil.com\n")

    return {
        "input": str(inp),
        "brno_dir": str(brno_dir),
        "fdns": str(fdns),
        "block": str(block),
        "db": str(tmp_path / "work.db"),
        "out": str(tmp_path / "enriched.parquet"),
    }


def test_full_pipeline(fixtures):
    pipeline.run(
        input_path=fixtures["input"],
        db=fixtures["db"],
        output=fixtures["out"],
        brno_dir=[fixtures["brno_dir"]],
        rapid7_fdns=fixtures["fdns"],
        blocklist=[fixtures["block"]],
        fmt="both",
    )

    df = pd.read_parquet(fixtures["out"]).set_index("domain")

    assert set(df.index) == {
        "example.com", "evil.com", "malware.test",
        "onlyfdns.com", "onlyblock.com", "nodata.com",
    }

    # Brno DNS + TLS, benign label.
    assert df.loc["example.com", "a"] == "93.184.216.34"  # not overwritten by FDNS 1.1.1.1
    assert df.loc["example.com", "tls_protocol"] == "TLSv1.3"
    assert df.loc["example.com", "threat_label"] == "benign"

    # Brno phishing label, blocklist source merged in.
    assert df.loc["evil.com", "threat_label"] == "phishing"
    assert df.loc["evil.com", "threat_sources"] == "urlhaus"

    assert df.loc["malware.test", "threat_label"] == "malware"

    # Rapid7-only domain.
    assert df.loc["onlyfdns.com", "a"] == "8.8.8.8"

    # Blocklist-only domain (urlhaus list -> malware label).
    assert df.loc["onlyblock.com", "threat_label"] == "malware"
    assert df.loc["onlyblock.com", "threat_sources"] == "urlhaus"

    # Domain with no matches survives with empty enrichment.
    assert pd.isna(df.loc["nodata.com", "a"])

    # CSV companion also written.
    import os
    assert os.path.exists(fixtures["out"].replace(".parquet", ".csv"))


def test_resume_across_processes(fixtures):
    # First "process": normalize + brno only.
    store = Store(fixtures["db"])
    pipeline.stage_normalize(store, fixtures["input"])
    pipeline.stage_brno(store, [fixtures["brno_dir"]], set())
    assert store.stage_done("brno") is True
    store.close()

    # Second "process": brno must be skipped, data intact.
    store2 = Store(fixtures["db"])
    matched = pipeline.stage_brno(store2, [fixtures["brno_dir"]], set())
    assert matched == 0  # skipped, nothing re-matched
    row = next(r for r in store2.iter_rows(10) if r["domain"] == "example.com")
    assert json.loads(row["a"]) == ["93.184.216.34"]
    store2.close()


def test_force_reruns_stage(fixtures):
    store = Store(fixtures["db"])
    pipeline.stage_normalize(store, fixtures["input"])
    pipeline.stage_brno(store, [fixtures["brno_dir"]], set())
    # Force re-runs and re-matches.
    matched = pipeline.stage_brno(store, [fixtures["brno_dir"]], {"brno"})
    assert matched == 3
    store.close()


def test_offline_dossier(tmp_path):
    """Full Domain-Dossier-style enrichment, entirely offline (no network)."""
    import json as _json
    from domain_enrich import pipeline

    inp = tmp_path / "d.txt"
    inp.write_text("ru.yummyani.me\n")

    # Brno fixture carrying DNS (incl SOA/TXT) + an RDAP whois object.
    brno_dir = tmp_path / "brno"
    brno_dir.mkdir()
    (brno_dir / "benign_cesnet.json").write_text(_json.dumps([{
        "domain_name": "ru.yummyani.me",
        "dns": {
            "A": [{"value": "62.233.36.139"}],
            "NS": [{"value": "hope.ns.cloudflare.com"}],
            "TXT": [{"value": "v=spf1 -all"}],
            "SOA": {"server": "ns1.royale-ix.net", "serial": 2026061601},
        },
        "rdap": {
            "ldhName": "yummyani.me",
            "port43": "whois.nic.me",
            "status": ["client transfer prohibited"],
            "secureDNS": {"delegationSigned": True},
            "events": [
                {"eventAction": "registration", "eventDate": "2022-03-08T15:47:10Z"},
                {"eventAction": "expiration", "eventDate": "2027-03-08T15:47:10Z"},
            ],
            "entities": [{
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "1910"}],
                "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc"]]],
            }],
            "nameservers": [{"ldhName": "hope.ns.cloudflare.com"}],
        },
    }]))

    rir = tmp_path / "ripe.txt"
    rir.write_text(
        "inetnum: 62.233.36.128 - 62.233.36.255\nnetname: ROYALE\n"
        "country: NL\norg: ORG-RB164\n\n"
        "organisation: ORG-RB164\norg-name: RoyaleHosting BV\nabuse-c: RB-AB\n\n"
        "role: abuse\nnic-hdl: RB-AB\nabuse-mailbox: abuse@royalehosting.nl\n"
    )

    tranco = tmp_path / "tranco.csv"
    tranco.write_text("1,google.com\n500000,ru.yummyani.me\n")

    out_csv = tmp_path / "out.csv"
    pipeline.run(
        input_path=str(inp), db=str(tmp_path / "w.db"),
        output=str(out_csv),
        brno_dir=[str(brno_dir)], rir_dump=[str(rir)], tranco=str(tranco),
        fmt="csv",
    )

    import pandas as pd
    df = pd.read_csv(str(out_csv)).set_index("domain")
    r = df.loc["ru.yummyani.me"]
    # DNS records
    assert r["ns"] == "hope.ns.cloudflare.com"
    assert r["txt"] == "v=spf1 -all"
    assert "royale-ix.net" in r["soa"]
    # Domain whois (from Brno RDAP)
    assert r["registrar"] == "Cloudflare, Inc"
    assert str(r["registrar_ianaid"]) == "1910"
    assert r["created_date"] == "2022-03-08T15:47:10Z"
    assert r["dnssec"] == "signedDelegation"
    # Network whois (from RIR dump)
    assert r["net_org"] == "RoyaleHosting BV"
    assert r["net_abuse_email"] == "abuse@royalehosting.nl"
    assert r["net_country"] == "NL"
    # Popularity
    assert int(r["popularity_rank"]) == 500000
