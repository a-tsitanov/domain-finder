import pytest

from domain_enrich.sources.rdap import parse_rdap


# A realistic RDAP domain response (as found in the Brno dataset's `rdap` field
# or any offline RDAP dump), modelled on the .me registry answer for yummyani.me.
SAMPLE = {
    "objectClassName": "domain",
    "ldhName": "yummyani.me",
    "port43": "whois.nic.me",
    "status": ["client transfer prohibited"],
    "secureDNS": {"delegationSigned": True},
    "events": [
        {"eventAction": "registration", "eventDate": "2022-03-08T15:47:10Z"},
        {"eventAction": "last changed", "eventDate": "2024-12-31T16:48:29Z"},
        {"eventAction": "expiration", "eventDate": "2027-03-08T15:47:10Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "1910"}],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Cloudflare, Inc"],
            ]],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["email", {}, "text", "abuseteam@cloudflare.com"],
                    ]],
                },
            ],
        },
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "REDACTED"],
                ["org", {}, "text", "Privacy Org"],
                ["adr", {}, "text", ["", "", "", "", "Moscovskaya Oblast", "", "RU"]],
            ]],
        },
    ],
    "nameservers": [
        {"ldhName": "hope.ns.cloudflare.com"},
        {"ldhName": "brett.ns.cloudflare.com"},
    ],
}


def test_parse_registrar_and_iana_id():
    out = parse_rdap(SAMPLE)
    assert out["registrar"] == "Cloudflare, Inc"
    assert out["registrar_ianaid"] == "1910"


def test_parse_dates():
    out = parse_rdap(SAMPLE)
    assert out["created_date"] == "2022-03-08T15:47:10Z"
    assert out["updated_date"] == "2024-12-31T16:48:29Z"
    assert out["expires_date"] == "2027-03-08T15:47:10Z"


def test_parse_registrant_org_and_country():
    out = parse_rdap(SAMPLE)
    assert out["registrant_org"] == "Privacy Org"
    assert out["registrant_country"] == "RU"


def test_parse_abuse_email_nested():
    out = parse_rdap(SAMPLE)
    assert out["abuse_email"] == "abuseteam@cloudflare.com"


def test_parse_status_and_dnssec_and_ns():
    out = parse_rdap(SAMPLE)
    assert out["domain_status"] == "client transfer prohibited"
    assert out["dnssec"] == "signedDelegation"
    assert out["nameservers"] == ["hope.ns.cloudflare.com", "brett.ns.cloudflare.com"]
    assert out["whois_server"] == "whois.nic.me"


def test_parse_empty_doc():
    assert parse_rdap({}) == {}
    assert parse_rdap(None) == {}


# Brno's flattened RDAP shape: direct *_date fields, entities as a dict keyed by
# role with {name, handle, email}, nameservers as strings, dnssec as a bool.
BRNO_SHAPE = {
    "name": "4digitalsignage.com",
    "handle": "DOM123",
    "whois_server": "whois.godaddy.com",
    "registration_date": "2007-05-15T03:38:44Z",
    "last_changed_date": "2023-02-21T13:19:09Z",
    "expiration_date": "2024-05-15T03:38:44Z",
    "entities": {
        "registrar": [{"handle": "146", "name": "GoDaddy.com, LLC"}],
        "registrant": [{"name": "Domains By Proxy, LLC"}],
        "abuse": [{"email": "abuse@godaddy.com"}],
    },
    "nameservers": ["PDNS01.DOMAINCONTROL.COM", "PDNS02.DOMAINCONTROL.COM"],
    "status": ["client delete prohibited", "client renew prohibited"],
    "dnssec": False,
}


def test_parse_brno_flattened_shape():
    out = parse_rdap(BRNO_SHAPE)
    assert out["registrar"] == "GoDaddy.com, LLC"
    assert out["registrar_ianaid"] == "146"
    assert out["registrant_org"] == "Domains By Proxy, LLC"
    assert out["abuse_email"] == "abuse@godaddy.com"
    assert out["created_date"] == "2007-05-15T03:38:44Z"
    assert out["updated_date"] == "2023-02-21T13:19:09Z"
    assert out["expires_date"] == "2024-05-15T03:38:44Z"
    assert out["nameservers"] == ["pdns01.domaincontrol.com", "pdns02.domaincontrol.com"]
    assert out["domain_status"] == "client delete prohibited;client renew prohibited"
    assert out["dnssec"] == "unsigned"
    assert out["whois_server"] == "whois.godaddy.com"


def test_parse_brno_date_still_wrapped():
    # If a dump wasn't ejson-unwrapped, dates may still be {"$date": ...}.
    doc = {"name": "x.com", "registration_date": {"$date": "2020-01-01T00:00:00Z"}}
    assert parse_rdap(doc)["created_date"] == "2020-01-01T00:00:00Z"
