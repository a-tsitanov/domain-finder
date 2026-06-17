#!/usr/bin/env bash
# Download every FREELY available offline database into data/.
# This step needs the internet; afterwards the pipeline runs fully offline.
#
# Sources that need an account/agreement are NOT fetched here:
#   - MaxMind official (use the mirror below, or your licensed copy)
#   - Rapid7 FDNS (access closed since 2022)
#   - ARIN / LACNIC bulk whois (registration required)
#
# Usage:
#   scripts/fetch-data.sh           # everything (incl. Brno ~16 GB)
#   SKIP_BRNO=1 scripts/fetch-data.sh   # skip the giant Brno dataset
set -euo pipefail
cd "$(dirname "$0")/.."
DATA="data"
mkdir -p "$DATA/brno" "$DATA/rir" "$DATA/blocklists" "$DATA/rdap"

dl() {  # dl <url> <output>
  echo ">> $2"
  curl -fSL --retry 3 --retry-delay 2 -C - -o "$2" "$1" || echo "   FAILED: $1"
}

echo "=== GeoLite2 (City + ASN) ==="
dl "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb" "$DATA/GeoLite2-City.mmdb"
dl "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"  "$DATA/GeoLite2-ASN.mmdb"

echo "=== Blocklists ==="
dl "https://urlhaus.abuse.ch/downloads/csv_recent/"           "$DATA/blocklists/urlhaus.csv"
dl "https://threatfox.abuse.ch/export/csv/recent/"            "$DATA/blocklists/threatfox.csv"
dl "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" "$DATA/blocklists/stevenblack_hosts.txt"
# domain phishing feeds
dl "https://openphish.com/feed.txt"                           "$DATA/blocklists/openphish.txt"
dl "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt" \
   "$DATA/blocklists/phishing_database.txt"

echo "=== IP/CIDR threat feeds (Feodo / SSLBL / Spamhaus DROP) ==="
mkdir -p "$DATA/ipthreat"
dl "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"  "$DATA/ipthreat/feodo_ipblocklist.txt"
dl "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"      "$DATA/ipthreat/sslbl.txt"
dl "https://www.spamhaus.org/drop/drop.txt"                   "$DATA/ipthreat/drop.txt"
dl "https://www.spamhaus.org/drop/edrop.txt"                  "$DATA/ipthreat/edrop.txt"

echo "=== Popularity (Tranco + Umbrella + Majestic + DomCop) ==="
mkdir -p "$DATA/popularity"
unzip_csv() {  # unzip_csv <url> <out.csv>
  dl "$1" "$2.zip"
  [ -f "$2.zip" ] && python3 -c "import zipfile; z=zipfile.ZipFile('$2.zip'); open('$2','wb').write(z.read([n for n in z.namelist() if n.endswith('.csv')][0]))" \
    && rm -f "$2.zip" && echo "   -> $2"
}
unzip_csv "https://tranco-list.eu/top-1m.csv.zip"                       "$DATA/popularity/tranco.csv"
unzip_csv "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip" "$DATA/popularity/umbrella.csv"
dl "https://downloads.majestic.com/majestic_million.csv"               "$DATA/popularity/majestic_million.csv"
unzip_csv "https://www.domcop.com/files/top/top10milliondomains.csv.zip" "$DATA/popularity/domcop_top10m.csv"

echo "=== PeeringDB (ASN -> org/type) ==="
dl "https://www.peeringdb.com/api/net"                        "$DATA/peeringdb_net.json"

# CT dumps and DNS zone files are large / access-gated (crt.sh bulk, ICANN CZDS):
# put your exported files here and they will be picked up automatically.
mkdir -p "$DATA/ct" "$DATA/zones"

echo "=== RIR whois dumps (RIPE + APNIC + AFRINIC) — network whois by IP ==="
# RIPE (Europe / Russia)
for f in inetnum inet6num organisation role; do
  dl "https://ftp.ripe.net/ripe/dbase/split/ripe.db.${f}.gz" "$DATA/rir/ripe.db.${f}.gz"
done
# APNIC (Asia/Pacific, incl. China .cn)
for f in inetnum inet6num organisation irt role; do
  dl "https://ftp.apnic.net/apnic/whois/apnic.db.${f}.gz" "$DATA/rir/apnic.db.${f}.gz"
done
# AFRINIC (Africa) — single combined dump
dl "https://ftp.afrinic.net/pub/dbase/afrinic.db.gz" "$DATA/rir/afrinic.db.gz"

if [ "${SKIP_BRNO:-0}" != "1" ]; then
  echo "=== Brno dataset (Zenodo 14332167) — ~16 GB, DNS/TLS/RDAP/labels ==="
  BASE="https://zenodo.org/api/records/14332167/files"
  for f in benign_umbrella.json benign_cesnet.json phishing.json malware.json; do
    dl "$BASE/$f/content" "$DATA/brno/$f"
  done
else
  echo "=== Brno skipped (SKIP_BRNO=1) ==="
fi

echo
echo ">> Done. data/ now contains:"
du -sh "$DATA"/* 2>/dev/null || true
