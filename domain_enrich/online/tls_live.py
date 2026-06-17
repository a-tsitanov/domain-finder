"""Live TLS handshake (async).

Opens a TLS connection to ``<domain>:443`` and records the negotiated cipher,
protocol version, and the certificate's Subject Alternative Names. Replaces the
TLS data the offline pipeline read from Brno / Certificate Transparency.

SANs require a parsed peer certificate, which the ``ssl`` module only returns
for a verified handshake. We therefore try a verifying handshake first (captures
cipher + protocol + SANs); if the cert is invalid/self-signed we retry without
verification to still capture cipher + protocol. No third-party cert parser is
needed.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Dict, List, Optional


def _sans_from_cert(cert: Optional[dict]) -> List[str]:
    if not cert:
        return []
    out: List[str] = []
    for typ, val in cert.get("subjectAltName", ()):  # ('DNS', 'example.com')
        if typ.upper() == "DNS":
            out.append(val.lower().rstrip("."))
    return list(dict.fromkeys(out))


async def _handshake(host: str, port: int, ctx: ssl.SSLContext,
                     timeout: float) -> Dict[str, object]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
        timeout=timeout,
    )
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        info: Dict[str, object] = {}
        if ssl_obj is not None:
            cipher = ssl_obj.cipher()          # (name, protocol, secret_bits)
            if cipher:
                info["cipher"] = cipher[0]
            version = ssl_obj.version()
            if version:
                info["protocol"] = version
            try:
                sans = _sans_from_cert(ssl_obj.getpeercert())
            except ValueError:
                sans = []
            if sans:
                info["sans"] = sans
        return info
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def handshake(domain: str, port: int = 443, timeout: float = 8.0,
                    opener=None) -> Dict[str, object]:
    """Return ``{"tls": {...}}`` for ``domain`` or ``{}`` if unreachable.

    ``opener(host, port, ctx, timeout)`` is injectable for testing; it defaults
    to the real async TLS handshake.
    """
    opener = opener or _handshake

    # Verifying context: yields SANs when the cert chain is valid.
    verify_ctx = ssl.create_default_context()
    try:
        info = await opener(domain, port, verify_ctx, timeout)
    except Exception:
        info = {}

    # Retry unverified to still capture cipher/protocol on invalid certs.
    if not info:
        noverify = ssl.create_default_context()
        noverify.check_hostname = False
        noverify.verify_mode = ssl.CERT_NONE
        try:
            info = await opener(domain, port, noverify, timeout)
        except Exception:
            info = {}

    return {"tls": info} if info else {}
