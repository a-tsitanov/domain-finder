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


def test_check_command_is_wired(tmp_path, monkeypatch):
    import domain_enrich.online.checker as checker_mod

    inp = tmp_path / "list.txt"
    inp.write_text("example.com\nbad.com\n")
    ok = tmp_path / "ok.tsv"
    bad = tmp_path / "bad.tsv"

    captured = {}

    def fake_run_check_sync(input_path, success_path, failed_path, **kwargs):
        captured.update(kwargs)
        captured["input_path"] = input_path
        # write minimal valid files so the command can echo a summary
        with open(success_path, "w") as fh:
            fh.write("resource\tstatus\tfinal_url\tvia_proxy\n")
        with open(failed_path, "w") as fh:
            fh.write("resource\tattempts\terror\n")
        return {"checked": 2, "ok": 0, "failed": 2}

    monkeypatch.setattr(checker_mod, "run_check_sync", fake_run_check_sync)

    result = CliRunner().invoke(cli, [
        "check", "--input", str(inp), "--success", str(ok),
        "--failed", str(bad), "--no-proxy", "--max-proxy-attempts", "10",
    ])
    assert result.exit_code == 0, result.output
    assert "checked 2" in result.output
    assert captured["max_proxy_attempts"] == 10
    assert captured["proxy_provider"] is None      # --no-proxy honored
    assert ok.read_text().splitlines()[0] == "resource\tstatus\tfinal_url\tvia_proxy"
    assert bad.read_text().splitlines()[0] == "resource\tattempts\terror"
