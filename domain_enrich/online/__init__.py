"""Online (live) enrichment adapters.

The offline pipeline joins a domain list against pre-downloaded dumps. This
package does the same enrichment by talking to free live services instead
(live DNS, RDAP, TLS handshake, ip-api/MaxMind, abuse.ch) and additionally
downloads each domain's rendered page with Playwright.

Everything here is async and built for high concurrency. The orchestration
lives in :mod:`domain_enrich.online.runner`; each ``*_live`` module is an
independently testable adapter that returns a dict of store columns.
"""
