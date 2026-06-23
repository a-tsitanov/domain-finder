# domain-enrich

Offline, resumable CLI microservice that enriches a list of domains (up to
~2M, one per line) by **joining against pre-downloaded open datasets** — no
active internet scanning by default. Results are written to a single flat table
(parquet and/or CSV).

## What it enriches

| Group | Attributes | Source |
|---|---|---|
| **DNS + IP** | A, AAAA, NS, MX, TXT, CNAME, SOA, PTR; derived unique IP list | Brno, Rapid7 FDNS, RDNS dump, zone files |
| **GeoIP + ASN** | country, city, coordinates; ASN, org, network, **type** | MaxMind GeoLite2 + PeeringDB |
| **TLS** | cipher, protocol, SANs | Brno dataset, Certificate Transparency dump |
| **Domain whois** | registrar, IANA id, whois server, created/updated/expiry, registrant org/country, abuse email, status, DNSSEC, nameservers | Brno RDAP field, offline RDAP dump |
| **Network whois** | inetnum range, netname, org, country, abuse email | RIR (RIPE/APNIC/AFRINIC) RPSL dump |
| **Popularity** | best rank across lists | Tranco + Umbrella + Majestic + DomCop |
| **Threat** | benign / phishing / malware, sources | Brno; domain lists (URLhaus/ThreatFox/StevenBlack/OpenPhish/Phishing.Database); IP/CIDR feeds (Feodo/SSLBL/Spamhaus DROP) |

> **Everything runs offline.** There are no live DNS/WHOIS/RDAP network calls.
> "Domain Dossier"-style data (domain whois, network whois, full DNS records)
> is produced by joining against pre-downloaded dumps: domain whois comes from
> the Brno dataset's embedded RDAP object (or a separate offline RDAP dump);
> network whois from a downloaded RIR database dump. You download each dump once,
> then all enrichment is local.

## Design principles

- **Staged pipeline over SQLite.** One row = one domain; each stage appends its
  own columns. Stages run cheapest-first with early filtering (geo only runs on
  domains that already have IPs).
- **Resumable on two levels.** Coarse `meta(stage, status)` skips finished
  stages; fine-grained per-row flags (`s_brno`/`s_rapid7`/`s_geo`/`s_threat`)
  let a re-run continue mid-stage without redoing finished rows. Kill the
  process anytime — re-run continues where it left off.
- **Sources are optional & independent.** Omit a source path and its stage is
  skipped with a warning; the rest still run.
- **Streaming throughout.** Large dumps are read in a single pass; the 2M-row
  output is written in chunks. Memory stays bounded by the number of matched
  domains, not the size of the source dumps.

```
[normalize] -> [brno] -> [rapid7] -> [zone] -> [geo] -> [netwhois] -> [peeringdb]
   -> [rdns] -> [threat] -> [ipthreat] -> [tranco] -> [ct] -> [rdap] -> [export]
```

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
```

Requires Python ≥ 3.10. Dependencies: click, ijson, geoip2, pandas, pyarrow,
idna, tqdm.

## Usage

Full run (every source is optional):

```bash
domain-enrich run \
  --input domains.txt \
  --db work.db \
  --output enriched.parquet \
  --brno-dir ./brno_data \
  --rapid7-fdns ./fdns_a.json.gz \
  --maxmind-city ./GeoLite2-City.mmdb --maxmind-asn ./GeoLite2-ASN.mmdb \
  --blocklist ./blocklists --ipthreat ./ipthreat \
  --rir-dump ./rir --peeringdb peeringdb_net.json \
  --tranco ./popularity \
  --zone ./zones --ct-dump ./ct --rdap-dump rdap_dump.jsonl \
  --fields domain,ips,geo_country,asn_org,asn_type,registrar,net_org,threat_label \
  --format both
```

Repeatable / directory-aware: `--brno-dir`, `--blocklist`, `--ipthreat`,
`--rir-dump`, `--zone`, `--ct-dump`, `--rdap-dump`, `--tranco` (a dir of lists =
popularity ensemble). Every path option also reads a `DE_*` env var, so under
the container you usually pass only `--input/--db/--output`. `--rdap-dump` is
only for domains Brno doesn't cover (Brno carries RDAP inline).

`--format` is `parquet` | `csv` | `both`. With `both`, the output path's
extension is swapped per format. `--fields` selects/orders output columns
(default: all). List them with `domain-enrich fields`.

Re-running is safe and idempotent: finished stages are skipped. Force a stage to
rerun with `--force STAGE` (repeatable), e.g. `--force threat`.

### Per-stage subcommands (debugging)

Each works over the same `--db` and is independently resumable:

```bash
domain-enrich normalize --input domains.txt --db work.db
domain-enrich brno      --brno-dir ./brno_data --db work.db [--force]
domain-enrich rapid7    --rapid7-fdns ./fdns_a.json.gz --db work.db [--force]
domain-enrich geo       --maxmind-city ./City.mmdb --maxmind-asn ./ASN.mmdb --db work.db [--force]
domain-enrich zone      --zone ./zones --db work.db [--force]
domain-enrich netwhois  --rir-dump ./rir --db work.db [--force]
domain-enrich peeringdb --peeringdb peeringdb_net.json --db work.db [--force]
domain-enrich threat    --blocklist ./blocklists --db work.db [--force]
domain-enrich ipthreat  --ipthreat ./ipthreat --db work.db [--force]
domain-enrich tranco    --tranco ./popularity --db work.db [--force]
domain-enrich ct        --ct-dump ./ct --db work.db [--force]
domain-enrich rdap      --rdap-dump rdap_dump.jsonl --db work.db [--force]
domain-enrich export    --db work.db --output enriched.parquet --format both
```

## Where to get the datasets

| Source | Link | Notes |
|---|---|---|
| **Brno BUT dataset** | Zenodo record **14332167** (CC BY 4.0) | Richest source: DNS, TLS, RDAP, IP, GeoIP, and a ready threat label. MongoDB Extended JSON arrays. Threat label is taken from the file name (`benign_*` → benign, `phishing*` → phishing, `malware*` → malware). `schema.json` is ignored. |
| **Rapid7 Open Data / Project Sonar FDNS** | sonardata.rapid7.com (⚠️ free access closed since 2022) | Forward DNS dump as gzip JSON-lines (`{"name","type","value"}`). Streamed line by line; only A/AAAA for matched domains kept. Alternatives: OpenINTEL (academic), CZDS zones. |
| **MaxMind GeoLite2 City + ASN** | https://www.maxmind.com (GeoLite2, free with account) | `.mmdb` files; fully offline, O(1) lookups. |
| **URLhaus** | https://urlhaus.abuse.ch | CSV / plain. |
| **ThreatFox** | https://threatfox.abuse.ch | CSV. |
| **PhishTank** | https://phishtank.org | CSV (the parser ignores the `phish_detail_url` reference column). |
| **StevenBlack hosts** | https://github.com/StevenBlack/hosts | hosts format (`0.0.0.0 domain`). |
| **OpenPhish** | https://openphish.com/feed.txt | phishing URL feed → domain. |
| **Phishing.Database** | github.com/mitchellkrogza/Phishing.Database | large phishing domain lists. |
| **Feodo / SSLBL** | feodotracker.abuse.ch · sslbl.abuse.ch | C2/botnet **IP** lists → matched by the domain's IP (`ipthreat` stage). |
| **Spamhaus DROP / EDROP** | https://www.spamhaus.org/drop/ | hijacked **CIDR** blocks → matched by IP (`ipthreat`). |
| **Tranco / Umbrella / Majestic / DomCop** | tranco-list.eu · s3 umbrella · downloads.majestic.com · domcop.com | popularity lists; the **best (smallest) rank** across them is kept. |
| **PeeringDB** | https://www.peeringdb.com/api/net | JSON keyed by ASN → operator name + network type. |
| **RIR dumps (network whois)** | RIPE: ftp.ripe.net/ripe/dbase/split/ · APNIC: ftp.apnic.net/apnic/whois/ · AFRINIC: ftp.afrinic.net/pub/dbase/ | RPSL dumps (`inetnum`/`inet6num` + `organisation` + abuse `role`/`irt`). Parsed offline, matched by IP for the most specific network. ARIN/LACNIC need registration. |
| **Certificate Transparency** | crt.sh export / CT log dump | (optional) cert records → SANs/subdomains + TLS for domains Brno missed. |
| **DNS zone files** | ICANN CZDS (czds.icann.org) | (optional) gTLD zones → forward DNS (NS/A/AAAA); free with application. |

For **domain whois** (registrar, dates, registrant, DNSSEC, nameservers) the
pipeline reads the **RDAP object already embedded in the Brno dataset** — no
network. If you have a separate offline RDAP dump (JSON-lines or a JSON array of
RDAP responses), feed it with `--rdap-dump` to cover domains Brno misses.

The blocklist parser auto-detects hosts / CSV / plain formats and rejects IP
literals. It also recovers a CSV header that a feed hides inside its comment
block (URLhaus does this), so it extracts the malicious `url` column rather than
the feed's own `urlhaus_link` infrastructure domain. The threat **label** is
inferred from the list name (`*phish*` → phishing, `urlhaus`/`threatfox` →
malware, otherwise `blocklisted`); when several lists hit one domain the
strongest label wins, and it never downgrades a richer `phishing`/`malware`
label already set by the Brno dataset (writers use `COALESCE`).

> Note: `.ru` is not specifically handled. "Today-fresh" accuracy is not a goal —
> recent static snapshots are expected and sufficient. VirusTotal is
> intentionally not used (rate limits make 2M domains impractical).

## Output schema

`domain, original, a, aaaa, ns, mx, txt, cname, soa, ptr, ips, tls_cipher,
tls_protocol, tls_sans, geo_country, geo_city, geo_lat, geo_lon, asn, asn_org,
asn_network, asn_type, net_range, net_name, net_org, net_country, net_abuse_email,
popularity_rank, registrar, registrar_ianaid, whois_server, created_date,
updated_date, expires_date, registrant_org, registrant_country, abuse_email,
domain_status, dnssec, nameservers, threat_label, threat_type, threat_sources`

List-valued columns (`a`/`aaaa`/`ns`/`mx`/`txt`/`cname`/`ptr`/`ips`/`nameservers`/
`tls_sans`) are `;`-joined. Run `domain-enrich fields` to list them.

## Single-domain lookup (Domain Dossier)

For an ad-hoc, one-domain report (no files written), use `lookup`:

```bash
domain-enrich lookup ru.yummyani.me            # full dossier (all sections)
domain-enrich lookup ru.yummyani.me --compact  # hide empty fields/sections
domain-enrich lookup ru.yummyani.me --json     # JSON object
```

By default it prints **every section and field** (empty values shown as `·`,
like a Domain Dossier table): Address lookup / DNS records, Domain Whois,
Network Whois, GeoIP + ASN, TLS, Popularity / Threat. `--compact` drops the
empties. Source paths default to `DE_*` environment variables, so once those are
set (the container presets them) you just type the domain.

## Containerized offline runner

The service ships as a runner container; the (large) databases are **mounted**,
not baked in, so they travel separately. Layout:

```
data/    -> /data   (read-only)  all offline databases
work/    -> /work               SQLite working DB + output tables
input/   -> /input              your domain lists
```

Build locally and run like a CLI (the container's entrypoint *is*
`domain-enrich`):

```bash
docker compose build
./scripts/de lookup ru.yummyani.me
./scripts/de run --input /input/domains.txt \
                 --db /work/work.db --output /work/enriched.parquet --format both
./scripts/de fields
```

The runner has `network_mode: none` — it **cannot** touch the network, which
enforces the offline guarantee. Source paths are preset via `DE_*` env vars in
`docker-compose.yml`, so `run` usually only needs `--input/--db/--output`.

Download all freely-available bases automatically (needs internet; run once):

```bash
scripts/fetch-data.sh            # GeoLite2 + blocklists + Tranco + RIR dumps + Brno (~16 GB)
SKIP_BRNO=1 scripts/fetch-data.sh   # skip the giant Brno dataset
```

Populate `data/` like this (omit any you don't have; that stage just skips):

```
data/
  GeoLite2-City.mmdb  GeoLite2-ASN.mmdb
  brno/               # Brno JSON files (DNS+TLS+RDAP+labels)
  fdns.json.gz        # optional Rapid7-style forward DNS
  rdns.json.gz        # optional reverse DNS (PTR)
  rir/                # RIR RPSL whois dumps -> network whois
  rdap/               # optional standalone RDAP dump
  blocklists/         # URLhaus/ThreatFox/StevenBlack/OpenPhish/Phishing.Database
  ipthreat/           # Feodo / SSLBL / Spamhaus DROP (IP/CIDR)
  popularity/         # tranco.csv umbrella.csv majestic_million.csv domcop_top10m.csv
  peeringdb_net.json  # PeeringDB (ASN -> org/type)
  ct/                 # optional Certificate Transparency dump
  zones/              # optional CZDS/BIND zone files
```

### Moving it to an air-gapped host

```bash
./scripts/build-offline.sh          # builds image + packs dist/domain-enrich-offline.tar.gz
```

Copy `dist/domain-enrich-offline.tar.gz` (and your populated `data/`) to the
offline host, then:

```bash
tar xzf domain-enrich-offline.tar.gz
docker load -i domain-enrich-image.tar
./scripts/de lookup example.com
```

See `OFFLINE-README.md` inside the bundle for the full procedure.

## Development

```bash
pip install -e '.[dev]'
pytest -q
```

Tests cover normalization, the blocklist parser (hosts/CSV/plain), MongoDB
Extended-JSON unwrap, the store's COALESCE/resume semantics, each source
adapter, export, and a full mini end-to-end run including cross-process resume.

## Online mode (live enrichment + page download)

The offline mode joins against pre-downloaded dumps. **Online mode** does the
same enrichment with **live, free services** — no datasets to download — and
additionally **downloads each domain's rendered page** with a headless browser
(Playwright). It is fully **async** for high throughput and **resumable** just
like the offline pipeline.

```
[normalize] -> per-domain async workers:
   dns(live) -> tls(handshake) -> rdap(domain whois) -> geo/ASN
            -> netwhois(IP RDAP) -> threat(abuse.ch) -> popularity -> render
   -> write <domain>.dossier.gz  +  aggregate parquet/CSV index
```

### Sources (all free)

| Group | Online tool | Key |
|---|---|---|
| DNS (A/AAAA/NS/MX/TXT/CNAME/SOA + PTR) | live resolve (dnspython async) | — |
| TLS (cipher/protocol/SANs) | live TLS handshake | — |
| Domain whois | RDAP via `rdap.org/domain/<d>` | — |
| Network whois | RDAP via `rdap.org/ip/<ip>` (ARIN/RIPE/APNIC) | — |
| GeoIP + ASN | MaxMind `.mmdb` (fast path) or **ip-api.com** (45/min) | — |
| Threat | URLhaus + ThreatFox APIs; IP/CIDR feeds | abuse.ch (free) |
| Popularity | Cloudflare Radar | CF token |
| **Rendered page** | **Playwright** (headless Chromium) | — |

DNS/RDAP/TLS are effectively unlimited; the binding limits are **ip-api
(45/min)** and **Playwright RAM**. The biggest speed lever is **caching IP- and
ASN-keyed lookups** (a network shared by many domains is fetched once).

### Install

```bash
pip install -e '.[online]'
python -m playwright install chromium   # one-time browser download
```

### Usage

```bash
domain-enrich run-online \
  --input domains.txt \
  --db work.db \
  --dossier-dir dossiers \
  --output agg.parquet --format both \
  --concurrency 100 --render-concurrency 12 \
  --maxmind-city ./GeoLite2-City.mmdb --maxmind-asn ./GeoLite2-ASN.mmdb \
  --ipthreat ./ipthreat --abuse-key "$DE_ABUSECH_KEY"
```

- **Per-domain artifact:** `dossiers/<domain>.dossier.gz` — a single gzip(JSON)
  with every enrichment field **plus** the rendered `page_html` and `page_*`
  metadata. Self-contained.
- **Aggregate index:** `--output` writes the same flat parquet/CSV table as the
  offline mode (without `page_html`, with `page_*` columns).
- **Resumable:** kill anytime and re-run — finished domains (dossier present /
  `s_render` set) are skipped. `--force online` (or `--force render`) reprocesses.
- `--no-render` skips the page download (enrichment only).
- Keys are optional: omit `--abuse-key`/`--cf-token` and those stages skip.
  Without `--maxmind-*`, geo falls back to ip-api (rate-limited).

Single live dossier (no files):

```bash
domain-enrich lookup --online example.com            # live, all sections
domain-enrich lookup --online --render example.com --json   # include page_html
```

### Proxy fallback & availability checker

Page rendering retries through public SOCKS5 proxies when a site is unreachable
(up to 25 attempts per domain; proxy use is logged to stderr). Lists are pulled
from iplocate and proxifly and cached under `work/proxies-socks5.txt`.

    # disable, or point at your own list:
    domain-enrich run-online --input /input/domains.txt --db /work/work.db --no-proxy
    domain-enrich run-online --input /input/domains.txt --db /work/work.db \
        --proxy-file /data/socks5.txt --max-proxy-attempts 10

Check reachability of a list of resources (same proxy pool on failure):

    domain-enrich check --input /input/resources.txt \
        --success /work/reachable.tsv --failed /work/unreachable.tsv

`reachable.tsv`: `resource  status  final_url  via_proxy`.
`unreachable.tsv`: `resource  attempts  error`.

### Containerized online runner

A separate, network-enabled service built on the Playwright image (the offline
`runner` stays `network_mode: none`):

```bash
docker compose --profile online build runner-online
./scripts/de-online run-online --input /input/domains.txt \
    --db /work/work.db --dossier-dir /work/dossiers \
    --output /work/agg.parquet --concurrency 100 --render-concurrency 12
./scripts/de-online lookup --online --render example.com --json
```

## Possible extensions (not in v1)

- Optional `live resolve` stage (dnsx/massdns) for unmatched domains.
- Optional CT-log source for TLS where Brno has no coverage.
- Thin FastAPI facade (upload → background job → status/download).
- Scheduled auto-download/refresh of blocklists.
- LLM content analysis over the rendered page (intentionally out of scope now).
