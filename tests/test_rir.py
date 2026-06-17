import pytest

from domain_enrich.sources.rir import build_rir_index, run_rir
from domain_enrich.store import Store


RIPE_DUMP = """\
inetnum:        62.233.36.0 - 62.233.255.255
netname:        ROYALE-BIG
country:        NL
org:            ORG-RB164-RIPE
status:         ALLOCATED PA
source:         RIPE

inetnum:        62.233.36.128 - 62.233.36.255
netname:        ROYALE-62-233-36-128
country:        NL
org:            ORG-RB164-RIPE
status:         ASSIGNED PA
source:         RIPE

organisation:   ORG-RB164-RIPE
org-name:       RoyaleHosting BV
country:        NL
abuse-c:        RBAC10-RIPE
source:         RIPE

role:           RoyaleHosting BV Abuse contact role object
nic-hdl:        RBAC10-RIPE
abuse-mailbox:  abuse@royalehosting.nl
source:         RIPE

inet6num:       2a0b:64c0:fff1::/48
netname:        ROYALE-V6
country:        NL
org:            ORG-RB164-RIPE
source:         RIPE
"""


@pytest.fixture
def dump(tmp_path):
    p = tmp_path / "ripe.db.txt"
    p.write_text(RIPE_DUMP)
    return str(p)


def test_lookup_most_specific_range(dump):
    idx = build_rir_index([dump])
    out = idx.lookup("62.233.36.139")
    assert out["net_range"] == "62.233.36.128 - 62.233.36.255"  # /25, not the big block
    assert out["net_name"] == "ROYALE-62-233-36-128"
    assert out["net_org"] == "RoyaleHosting BV"
    assert out["net_country"] == "NL"
    assert out["net_abuse_email"] == "abuse@royalehosting.nl"


def test_lookup_ipv6(dump):
    idx = build_rir_index([dump])
    out = idx.lookup("2a0b:64c0:fff1::2")
    assert out["net_name"] == "ROYALE-V6"
    assert out["net_org"] == "RoyaleHosting BV"


def test_lookup_miss(dump):
    idx = build_rir_index([dump])
    assert idx.lookup("8.8.8.8") == {}


def test_placeholder_blocks_ignored(tmp_path):
    # RIPE/APNIC dumps include placeholder objects for ranges they don't manage
    # (delegated to ARIN). These must not be reported as a real network.
    dump = tmp_path / "ripe.txt"
    dump.write_text(
        "inetnum: 23.0.0.0 - 23.255.255.255\n"
        "netname: NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK\n"
        "descr: IPv4 address block not managed by the RIPE NCC\n"
        "country: EU\n"
    )
    idx = build_rir_index([str(dump)])
    assert idx.lookup("23.195.248.81") == {}


def test_reads_gzip_dump(tmp_path):
    import gzip
    gz = tmp_path / "ripe.db.gz"
    with gzip.open(gz, "wt") as fh:
        fh.write(RIPE_DUMP)
    idx = build_rir_index([str(gz)])
    out = idx.lookup("62.233.36.139")
    assert out["net_org"] == "RoyaleHosting BV"


def test_run_rir_writes_to_store(tmp_path, dump):
    store = Store(str(tmp_path / "w.db"))
    store.add_domains([("ru.yummyani.me", "ru.yummyani.me")])
    store.update_dns("ru.yummyani.me", ips=["62.233.36.139"])
    matched = run_rir(store, [dump])
    assert matched == 1
    row = next(r for r in store.iter_rows(10) if r["domain"] == "ru.yummyani.me")
    assert row["net_org"] == "RoyaleHosting BV"
    assert row["net_abuse_email"] == "abuse@royalehosting.nl"
    assert row["s_netwhois"] == 1
    store.close()


def test_bucketing_finds_specific_and_large_ranges(tmp_path):
    # A large enclosing range (spans many /16 buckets) plus a small nested one.
    # The bucketed lookup must still pick the most specific, and must find the
    # large range for a point only it covers.
    lines = [
        "inetnum: 10.0.0.0 - 10.255.255.255\nnetname: BIG\ncountry: US\norg: O1\n",
        "inetnum: 10.5.5.0 - 10.5.5.255\nnetname: SMALL\ncountry: US\norg: O2\n",
        "organisation: O1\norg-name: Big Corp\n",
        "organisation: O2\norg-name: Small Corp\n",
    ]
    dump = tmp_path / "r.txt"
    dump.write_text("\n".join(lines))
    idx = build_rir_index([str(dump)])
    assert idx.lookup("10.5.5.9")["net_org"] == "Small Corp"   # most specific
    assert idx.lookup("10.200.0.1")["net_org"] == "Big Corp"   # only the big one
    assert idx.lookup("11.0.0.1") == {}


def test_whole_space_range_ignored(tmp_path):
    dump = tmp_path / "apnic.txt"
    dump.write_text(
        "inetnum: 0.0.0.0 - 255.255.255.255\nnetname: ROOT\n"
        "descr: Internet Assigned Numbers Authority\norg: IANA\n"
    )
    idx = build_rir_index([str(dump)])
    assert idx.lookup("104.18.20.63") == {}


def test_corrupt_file_skipped(tmp_path):
    good = tmp_path / "ripe.txt"
    good.write_text("inetnum: 1.2.3.0 - 1.2.3.255\nnetname: GOOD\norg: O\n\n"
                    "organisation: O\norg-name: Good Corp\n")
    bad = tmp_path / "broken.db.gz"   # claims .gz but isn't gzip
    bad.write_bytes(b"\x2f\x1b not gzip at all")
    idx = build_rir_index([str(bad), str(good)])   # must NOT raise
    assert idx.lookup("1.2.3.4")["net_org"] == "Good Corp"
