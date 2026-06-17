import os
import tempfile

import pytest

from domain_enrich.normalize import normalize_domain, read_input


class TestNormalizeDomain:
    def test_plain_domain_lowercased(self):
        assert normalize_domain("Example.COM") == "example.com"

    def test_strips_http_scheme(self):
        assert normalize_domain("http://example.com") == "example.com"

    def test_strips_https_scheme(self):
        assert normalize_domain("https://example.com") == "example.com"

    def test_strips_path(self):
        assert normalize_domain("https://example.com/path/to/page") == "example.com"

    def test_strips_query(self):
        assert normalize_domain("example.com?utm=1&x=2") == "example.com"

    def test_strips_port(self):
        assert normalize_domain("example.com:8443") == "example.com"

    def test_strips_userinfo(self):
        assert normalize_domain("user:pass@example.com") == "example.com"

    def test_strips_scheme_userinfo_port_and_path(self):
        assert normalize_domain("https://user@sub.example.com:443/a/b?c=d") == "sub.example.com"

    def test_trailing_dot_removed(self):
        assert normalize_domain("example.com.") == "example.com"

    def test_surrounding_whitespace_trimmed(self):
        assert normalize_domain("  example.com  ") == "example.com"

    def test_internal_space_rejected(self):
        assert normalize_domain("exa mple.com") is None

    def test_no_dot_rejected(self):
        assert normalize_domain("localhost") is None

    def test_empty_rejected(self):
        assert normalize_domain("") is None
        assert normalize_domain("   ") is None

    def test_unicode_idn_to_punycode(self):
        # bücher.de -> xn--bcher-kva.de
        assert normalize_domain("bücher.de") == "xn--bcher-kva.de"

    def test_already_punycode_kept(self):
        assert normalize_domain("xn--bcher-kva.de") == "xn--bcher-kva.de"

    def test_unicode_uppercase_uts46(self):
        # uppercase unicode folded by uts46
        assert normalize_domain("BÜCHER.de") == "xn--bcher-kva.de"

    def test_garbage_returns_none(self):
        assert normalize_domain("!!!") is None

    def test_none_input(self):
        assert normalize_domain(None) is None


class TestReadInput:
    def test_yields_normalized_and_original_pairs(self):
        lines = ["Example.COM\n", "http://Foo.org/x\n", "garbage\n", "\n", "bücher.de\n"]
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.writelines(lines)
            path = fh.name
        try:
            rows = list(read_input(path))
        finally:
            os.unlink(path)
        assert ("example.com", "Example.COM") in rows
        assert ("foo.org", "http://Foo.org/x") in rows
        assert ("xn--bcher-kva.de", "bücher.de") in rows
        # garbage and blank lines are skipped
        assert all(norm is not None for norm, _ in rows)
        assert len(rows) == 3
