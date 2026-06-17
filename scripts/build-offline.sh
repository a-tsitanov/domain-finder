#!/usr/bin/env bash
# Build a self-contained bundle for moving domain-enrich to an OFFLINE host.
#
# This step runs ONLINE (it needs the base image + pip deps). It produces:
#   dist/domain-enrich-offline.tar.gz   <- copy this to the air-gapped host
# containing:
#   - domain-enrich-image.tar  (the runner image, `docker save`)
#   - docker-compose.yml, scripts/de
#   - data/ work/ input/ skeleton + OFFLINE-README.md
#
# The large databases are NOT included (they are user-supplied). Copy your
# populated data/ directory to the offline host alongside the unpacked bundle.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-domain-enrich:latest}"
DIST="dist"
BUNDLE="$DIST/bundle"

echo ">> Building image $IMAGE"
docker build -t "$IMAGE" .

echo ">> Staging bundle in $BUNDLE"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE"/{scripts,work,input}
mkdir -p "$BUNDLE"/data/{brno,rir,rdap,blocklists,ipthreat,popularity,ct,zones}

echo ">> Saving image (this can take a minute)"
docker save "$IMAGE" -o "$BUNDLE/domain-enrich-image.tar"

cp docker-compose.yml "$BUNDLE/"
cp scripts/de "$BUNDLE/scripts/de"
chmod +x "$BUNDLE/scripts/de"

cat > "$BUNDLE/OFFLINE-README.md" <<'EOF'
# domain-enrich — offline bundle

Everything here runs with NO network access.

## 1. Load the image (once, on the offline host)
```
docker load -i domain-enrich-image.tar
```

## 2. Put your databases under data/
```
data/
  GeoLite2-City.mmdb        # MaxMind GeoLite2 City
  GeoLite2-ASN.mmdb         # MaxMind GeoLite2 ASN
  brno/                     # Brno dataset JSON files (DNS+TLS+RDAP+labels)
  fdns.json.gz             # (optional) Rapid7-style forward-DNS dump
  rdns.json.gz             # (optional) reverse-DNS (PTR) dump
  rir/                      # RIR RPSL whois dumps (RIPE/APNIC/AFRINIC) -> network whois
  rdap/                     # (optional) standalone RDAP dump files
  blocklists/               # URLhaus/ThreatFox/StevenBlack/OpenPhish/Phishing.Database
  ipthreat/                 # Feodo / SSLBL / Spamhaus DROP (IP/CIDR threats)
  popularity/               # tranco.csv umbrella.csv majestic_million.csv domcop_top10m.csv
  peeringdb_net.json        # PeeringDB (ASN -> org/type)
  ct/                       # (optional) Certificate Transparency dump -> SANs
  zones/                    # (optional) CZDS/BIND zone files -> forward DNS
```
Any file/dir you omit just makes that enrichment stage skip — the rest run.

## 3. Run it like a CLI
Single-domain dossier (all sections, empty fields shown as "·"; --compact hides them):
```
./scripts/de lookup ru.yummyani.me
```
Batch enrichment of a list (put it in input/):
```
./scripts/de run --input /input/domains.txt \
                 --db /work/work.db \
                 --output /work/enriched.parquet --format both
```
Results land in work/. Source paths come from the DE_* env vars preset in
docker-compose.yml, so you normally only pass --input/--db/--output.

List output columns:  ./scripts/de fields
EOF

echo ">> Packing tarball"
mkdir -p "$DIST"
tar -C "$BUNDLE" -czf "$DIST/domain-enrich-offline.tar.gz" .

echo ">> Done: $DIST/domain-enrich-offline.tar.gz"
echo "   Copy it (and your populated data/ dir) to the offline host, then:"
echo "     tar xzf domain-enrich-offline.tar.gz && docker load -i domain-enrich-image.tar"
