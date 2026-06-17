"""Per-domain dossier files: ``<dossier-dir>/<domain>.dossier.gz``.

For large lists, each domain's full result — every flat enrichment field plus
the rendered ``page_html`` and ``page_*`` metadata — is written as a single
gzip-compressed JSON object. Self-contained and independent, so the run is
resumable file-by-file and the (large) HTML never bloats the SQLite DB or the
aggregate parquet/CSV.
"""

from __future__ import annotations

import gzip
import json
import os
from typing import Dict, Optional


def dossier_path(dossier_dir: str, domain: str) -> str:
    # Domains are punycode/ASCII after normalization, safe as filenames; guard
    # the few separator chars just in case.
    safe = domain.replace("/", "_").replace("\\", "_")
    return os.path.join(dossier_dir, f"{safe}.dossier.gz")


def write_dossier(dossier_dir: str, domain: str, record: Dict[str, object]) -> str:
    """Write ``record`` as gzip(JSON) and return the file path."""
    os.makedirs(dossier_dir, exist_ok=True)
    path = dossier_path(dossier_dir, domain)
    payload = json.dumps(record, ensure_ascii=False, default=str).encode("utf-8")
    tmp = f"{path}.tmp"
    with gzip.open(tmp, "wb") as fh:
        fh.write(payload)
    os.replace(tmp, path)  # atomic: a half-written dossier never looks complete
    return path


def read_dossier(path: str) -> Dict[str, object]:
    with gzip.open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def dossier_complete(dossier_dir: str, domain: str) -> bool:
    """True if a non-empty dossier already exists (used for resume)."""
    path = dossier_path(dossier_dir, domain)
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False
