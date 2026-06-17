# Online enrichment mode — design

**Date:** 2026-06-17
**Status:** approved

## Goal

Add an **online** counterpart to the existing offline `domain-enrich` pipeline.
Instead of joining a domain list against pre-downloaded dumps, the online mode
performs **live lookups against free tools/services** and additionally
**downloads the rendered page** of each domain via a headless browser
(Playwright). No LLM, no content analysis — the page is simply fetched and
stored.

The online mode reuses the existing framework (`store`, `pipeline`, `export`,
the output schema, the resume model) and adds a parallel set of async source
adapters plus a new `render` stage. The offline mode is untouched and keeps
working.

## Non-goals

- No LLM / content analysis. The rendered HTML is stored verbatim.
- No new output schema for the structured fields — the same flat columns are
  produced, just sourced live. Six `page_*` metadata columns are added.
- Not aiming for "today-fresh" beyond what a single live pass gives.

## Constraints discovered (free-tool limits, June 2026)

| Source | Free limit | Implication |
|---|---|---|
| Live DNS (dnspython) | none (resolver-bound) | hot path, effectively unlimited |
| TLS handshake (`ssl`) | none | ~1–3 s/host, needs reachability |
| RDAP (`rdap.org`) domain + IP | generous, no key | replaces domain & network whois |
| ip-api.com (geo+ASN) | 45 req/min, non-commercial | rate-limited; MaxMind `.mmdb` is the no-limit fast path |
| URLhaus / ThreatFox API | free auth key, fair-use | stage optional (skip without key) |
| Cloudflare Radar (popularity) | free, CF token | optional |
| Playwright render | none (local) | heaviest stage, RAM-bound |

The binding constraints are **ip-api (45/min)** and **Playwright RAM**, not
DNS/RDAP/TLS. The largest speed lever is **dedup/caching of IP- and
ASN-keyed lookups** (many domains share a network).

## Architecture

### Execution model — async, high concurrency

- **asyncio** core. A pool of **K concurrent domain-workers**; each worker runs
  one domain end-to-end through the online chain
  (`dns → tls → rdap → geo → netwhois → threat → render`) and emits its result.
  Per-domain end-to-end chaining maximizes pipelining and matches the
  per-domain dossier output.
- **HTTP**: a single shared `httpx.AsyncClient` (connection pool, HTTP/2) for all
  HTTP sources (RDAP, ip-api, abuse.ch, Cloudflare).
- **DNS**: `dns.asyncresolver` (dnspython, already a dependency).
- **TLS**: `asyncio.open_connection(ssl=...)`, capture negotiated cipher,
  protocol, peer-cert SANs.
- **Playwright** (async API): a pool of **M browser contexts** guarded by its own
  semaphore — render concurrency is capped independently (and below) the network
  concurrency because it is RAM-bound.
- **Rate limiters**: a token-bucket per source (ip-api 45/min, abuse.ch
  fair-use). They permit parallelism up to the limit and no further.
- **Caches** (the main speed lever): in-process caches keyed by
  `IP → geo`, `IP → netwhois CIDR`, `ASN → peeringdb`, `TLD → RDAP server`.
  Shared across workers so a network shared by many domains is fetched once.

### Store changes

Reuse `store.py`. Add via the existing `_MIGRATE_COLUMNS` mechanism:

- Columns: `page_path`, `page_http_status`, `page_final_url`, `page_bytes`,
  `page_fetched_at`, `page_error`.
- Row flags: `s_odns`, `s_otls`, `s_ordap`, `s_onet`, `s_ogeo`, `s_othreat`,
  `s_opop`, `s_render` (added to `ROW_FLAGS`, `_INDEXES`, `STAGE_FLAGS`).
- A `update_page(...)` COALESCE writer and a `update_tls_live(...)` /
  `update_geo`/`update_netwhois`/`update_rdap` reuse (writers already exist).

### SQLite under high concurrency

SQLite is single-writer. To keep resume + speed:

- WAL is already enabled.
- A single async **writer task** drains a bounded `asyncio.Queue` of pending
  writes and commits in **batches** (every N rows or T ms). All `sqlite3` calls
  run in a thread executor so they never block the event loop.
- Bounded queues give backpressure between fetch and write.

### Online adapters (`domain_enrich/online/`)

| Module | Replaces | Tool |
|---|---|---|
| `dns_live.py` | brno/rapid7/zone/rdns DNS | `dns.asyncresolver` (A/AAAA/NS/MX/TXT/CNAME/SOA + reverse PTR) |
| `tls_live.py` | brno/ct TLS | `asyncio.open_connection` + ssl → cipher/protocol/SANs |
| `rdap_live.py` | offline RDAP dump | `GET rdap.org/domain/<d>` → existing `sources.rdap.parse_rdap` |
| `netwhois_live.py` | RIR dump | `GET rdap.org/ip/<ip>` → range/netname/org/country/abuse |
| `geo_live.py` | MaxMind/PeeringDB | MaxMind `.mmdb` (default, no limit) or ip-api.com fallback |
| `threat_live.py` | blocklists/ipthreat | URLhaus + ThreatFox host API (auth key), IP/CIDR feeds |
| `popularity_live.py` | tranco | Cloudflare Radar API (optional) |
| `render.py` | — (new) | Playwright headless Chromium → rendered HTML |
| `ratelimit.py` | — | async token-bucket |
| `cache.py` | — | async keyed caches with single-flight |
| `writer.py` | — | batched async SQLite writer |
| `runner.py` | pipeline.run | async orchestrator (worker pool) |

RDAP and ipthreat **parsers are reused** (`sources.rdap.parse_rdap`,
`sources.ipthreat.IpThreat`); only the data acquisition differs.

### `render` stage and dossier output

- Playwright navigates to `https://<domain>` (fallback `http://`), waits for
  load, captures `page.content()` (post-JS DOM), final URL, HTTP status, byte
  size, and any error.
- **Per-domain artifact**: `<dossier-dir>/<domain>.dossier.gz` =
  `gzip(JSON)` of a single object: every flat enrichment field **plus**
  `page_html` and the `page_*` metadata. Self-contained.
- **Aggregate**: the existing `export` still writes a flat parquet/CSV over the
  whole list (without `page_html`, with the `page_*` metadata columns) as an
  index/overview.

### CLI

- `run-online --input --db --dossier-dir --output [--format] [--concurrency]
  [--render-concurrency] [--no-render] [--maxmind-city/--maxmind-asn]
  [--force STAGE]` — the full async run.
- `lookup --online <domain>` — single-domain live dossier (no files), reusing
  the same adapters with concurrency 1.
- `export` reused unchanged for the aggregate table.
- Config via env: `DE_ABUSECH_KEY`, `DE_CF_RADAR_TOKEN`, `DE_MAXMIND_CITY`,
  `DE_MAXMIND_ASN`, `DE_DOSSIER_DIR`.

### Output schema additions

`FLAT_FIELDS` gains: `page_path`, `page_http_status`, `page_final_url`,
`page_bytes`, `page_fetched_at`, `page_error`. `flatten_row` passes them
through. The dossier JSON additionally carries `page_html`.

### Dependencies

Add an optional extra `online = ["httpx>=0.27", "playwright>=1.44"]`.
`dnspython` is promoted to a base dependency (already installed). Playwright
browser binaries are installed via `playwright install chromium` (documented;
the online Docker image bakes them in).

### Docker

A new compose service `runner-online` built from `Dockerfile.online`
(base `mcr.microsoft.com/playwright/python`) **with** network access. The
offline `runner` (`network_mode: none`) is unchanged. The online service mounts
`work/` (db + dossiers + aggregate) and `input/`.

## Resume semantics

Per-row flags `s_*` (above) make every online stage independently resumable; a
re-run continues from where it stopped. `--force STAGE` clears a stage's flag.
Coarse `meta(stage,status)` skips finished stages. A completed `render` row is
skipped if its `<domain>.dossier.gz` already exists and `page_error` is null.

## Testing

- Unit: async DNS/TLS/RDAP/geo/threat adapters with mocked transports
  (monkeypatched `httpx` transport / async resolver / ssl). Reuse existing
  `parse_rdap` and `IpThreat` parser tests.
- `render`: mock the Playwright page object (no real browser in CI).
- Writer: batched async writer correctness + resume.
- Dossier: `<domain>.dossier.gz` round-trips to the expected JSON, includes
  `page_html`, and the aggregate export omits `page_html`.
- E2E: a mini online run with all transports mocked, including cross-process
  resume.

## Risks / mitigations

- **ip-api 45/min** throttles large runs → default geo to local MaxMind; ip-api
  is an explicit fallback. Cache by IP.
- **RDAP per-registry throttling** → cache by TLD/registrar server; polite
  concurrency; ret/backoff with jitter.
- **Playwright RAM** → separate, smaller render semaphore; reuse one browser,
  many contexts; per-page timeout; capture errors rather than aborting the run.
- **SQLite contention** → single batched writer task; never write from workers
  directly.
