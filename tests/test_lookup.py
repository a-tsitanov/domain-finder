import json

import pytest

from domain_enrich import pipeline


def test_lookup_domain_builds_dossier(tmp_path):
    brno_dir = tmp_path / "brno"
    brno_dir.mkdir()
    (brno_dir / "benign_cesnet.json").write_text(json.dumps([{
        "domain_name": "ru.yummyani.me",
        "dns": {"A": [{"value": "62.233.36.139"}], "NS": [{"value": "hope.ns.cloudflare.com"}]},
        "rdap": {
            "ldhName": "yummyani.me",
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc"]]],
            }],
        },
    }]))
    rir = tmp_path / "ripe.txt"
    rir.write_text(
        "inetnum: 62.233.36.0 - 62.233.36.255\nnetname: ROYALE\ncountry: NL\norg: O\n\n"
        "organisation: O\norg-name: RoyaleHosting BV\n"
    )

    row = pipeline.lookup_domain(
        "ru.yummyani.me", brno_dir=[str(brno_dir)], rir_dump=[str(rir)],
    )
    assert row["domain"] == "ru.yummyani.me"
    assert row["a"] == "62.233.36.139"
    assert row["registrar"] == "Cloudflare, Inc"
    assert row["net_org"] == "RoyaleHosting BV"


def test_lookup_domain_invalid():
    with pytest.raises(ValueError):
        pipeline.lookup_domain("not a domain")


def test_lookup_domain_no_sources_returns_bare_row():
    row = pipeline.lookup_domain("example.com")
    assert row["domain"] == "example.com"
    assert row["a"] is None
