from click.testing import CliRunner

from domain_enrich.cli import cli


def test_lookup_shows_all_fields_by_default():
    # No sources -> bare row; default mode must still print every section and
    # field, with a dash for empties (full dossier like centralops).
    res = CliRunner().invoke(cli, ["lookup", "example.com"])
    assert res.exit_code == 0
    assert "=== Domain Whois ===" in res.output
    assert "=== Network Whois ===" in res.output
    assert "registrar" in res.output
    assert "·" in res.output                      # empties shown as dash
    assert "example.com" in res.output


def test_lookup_compact_hides_empty():
    res = CliRunner().invoke(cli, ["lookup", "example.com", "--compact"])
    assert res.exit_code == 0
    # With nothing resolved, compact output has no empty whois section.
    assert "=== Domain Whois ===" not in res.output
    assert "example.com" in res.output


def test_lookup_json_unchanged():
    res = CliRunner().invoke(cli, ["lookup", "example.com", "--json"])
    assert res.exit_code == 0
    import json
    obj = json.loads(res.output)
    assert obj["domain"] == "example.com"
