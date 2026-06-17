"""Domain normalization and input reading.

A domain is normalized to a canonical, comparable form:
lowercased, with scheme/userinfo/path/query/port stripped, IDN encoded to
punycode. Anything that does not look like a domain returns ``None``.
"""

from __future__ import annotations

import re
from typing import Iterator, Optional, Tuple

import idna

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_ASCII_HOST_RE = re.compile(r"^[a-z0-9.\-_]+$")


def normalize_domain(raw: Optional[str]) -> Optional[str]:
    """Normalize a raw host/URL string into a bare punycode domain.

    Returns ``None`` for anything that is not a plausible domain.
    """
    if raw is None:
        return None

    s = raw.strip()
    if not s:
        return None

    # Strip scheme://
    s = _SCHEME_RE.sub("", s)

    # Strip path / query / fragment: everything from the first / ? #
    s = re.split(r"[/?#]", s, maxsplit=1)[0]

    # Strip userinfo (user:pass@)
    if "@" in s:
        s = s.rsplit("@", 1)[1]

    # Strip port. IPv6 literals (containing ':') are not domains, so a lone
    # trailing ":port" is the only colon case we care about.
    if ":" in s:
        s = s.split(":", 1)[0]

    # Trailing dot (FQDN root) is not meaningful for joins.
    s = s.rstrip(".")

    s = s.lower()

    if not s or " " in s or "." not in s:
        return None

    # Pure-ASCII hostnames are kept verbatim (covers already-punycode).
    if _ASCII_HOST_RE.match(s):
        return s

    # Otherwise treat as an IDN and encode to punycode.
    try:
        return idna.encode(s, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        return None


def read_input(path: str) -> Iterator[Tuple[str, str]]:
    """Yield ``(normalized, original)`` for each parseable line of ``path``.

    Blank lines and lines that fail normalization are skipped.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            original = line.strip()
            if not original:
                continue
            normalized = normalize_domain(original)
            if normalized is None:
                continue
            yield normalized, original
