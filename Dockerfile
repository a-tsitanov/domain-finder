# Runner image for domain-enrich. Datasets are NOT baked in — they are mounted
# at runtime from ./data (see docker-compose.yml), so the image stays small and
# the (large) offline databases are transferred separately.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY domain_enrich ./domain_enrich
RUN pip install .

# Conventional mount points (created so they exist even before volumes attach).
RUN mkdir -p /data /work /input

# Default dataset locations inside the container; override per deployment.
ENV DE_BRNO_DIR=/data/brno \
    DE_RAPID7_FDNS=/data/fdns.json.gz \
    DE_MAXMIND_CITY=/data/GeoLite2-City.mmdb \
    DE_MAXMIND_ASN=/data/GeoLite2-ASN.mmdb \
    DE_RIR_DUMP=/data/rir \
    DE_RDNS_DUMP=/data/rdns.json.gz \
    DE_TRANCO=/data/popularity \
    DE_BLOCKLIST=/data/blocklists \
    DE_RDAP_DUMP=/data/rdap \
    DE_ZONE=/data/zones \
    DE_IPTHREAT=/data/ipthreat \
    DE_PEERINGDB=/data/peeringdb_net.json \
    DE_CT_DUMP=/data/ct

# `domain-enrich` is the entrypoint, so `docker run <img> lookup example.com`
# and `docker run <img> run --input ...` work like a normal CLI.
ENTRYPOINT ["domain-enrich"]
CMD ["--help"]
