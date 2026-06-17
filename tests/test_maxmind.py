import pytest

from domain_enrich.sources.maxmind import lookup_ip


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeCityReader:
    def city(self, ip):
        if ip == "1.2.3.4":
            return _Obj(
                country=_Obj(iso_code="US"),
                city=_Obj(name="Mountain View"),
                location=_Obj(latitude=37.4, longitude=-122.1),
            )
        raise KeyError("not found")


class FakeAsnReader:
    def asn(self, ip):
        if ip == "1.2.3.4":
            return _Obj(
                autonomous_system_number=15169,
                autonomous_system_organization="Google LLC",
                network="1.2.3.0/24",
            )
        raise KeyError("not found")


def test_lookup_combines_city_and_asn():
    out = lookup_ip(FakeCityReader(), FakeAsnReader(), "1.2.3.4")
    assert out["geo_country"] == "US"
    assert out["geo_city"] == "Mountain View"
    assert out["geo_lat"] == 37.4
    assert out["geo_lon"] == -122.1
    assert out["asn"] == 15169
    assert out["asn_org"] == "Google LLC"
    assert out["asn_network"] == "1.2.3.0/24"


def test_lookup_handles_missing_ip():
    out = lookup_ip(FakeCityReader(), FakeAsnReader(), "9.9.9.9")
    assert out == {}


def test_lookup_city_only():
    out = lookup_ip(FakeCityReader(), None, "1.2.3.4")
    assert out["geo_country"] == "US"
    assert "asn" not in out
