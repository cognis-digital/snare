from snare.catalog import CATALOG
from snare.compile import merge, render
from snare.parse import parse

HOSTS = "# comment\n0.0.0.0 ads.example.com\n127.0.0.1 track.example.net\n0.0.0.0 www.dup.com # inline\n"
ADBLOCK = "! title\n||malware.example^\n||redirect.example.com^$third-party\nexample.com##.ad\n||good.example^\n"
DOMAINS = "phish.example.org\nnot a domain\nscam.example.io\n"


def test_catalog_integrity():
    assert len(CATALOG) >= 20
    names = [s["name"] for s in CATALOG]
    assert len(names) == len(set(names))
    cats = {"adguard", "ads", "tracking", "malware", "phishing-scam", "redirect-malvertising"}
    for s in CATALOG:
        assert s["url"].startswith("http") and s["category"] in cats
        assert s["fmt"] in ("hosts", "adblock", "domains")


def test_parse_hosts():
    d = parse(HOSTS, "hosts")
    assert d == {"ads.example.com", "track.example.net", "dup.com"}  # www. stripped


def test_parse_adblock_domain_rules_only():
    d = parse(ADBLOCK, "adblock")
    assert "malware.example" in d
    assert "good.example" in d
    assert "redirect.example.com" not in d  # $-option rule skipped (not a pure block)


def test_parse_domains():
    d = parse(DOMAINS, "domains")
    assert d == {"phish.example.org", "scam.example.io"}


def test_merge_dedupes():
    m = merge([{"a.com", "b.com"}, {"b.com", "c.com"}])
    assert m == {"a.com", "b.com", "c.com"}


def test_render_formats():
    doms = {"b.com", "a.com"}
    assert "0.0.0.0 a.com" in render(doms, "hosts")
    assert "||a.com^" in render(doms, "adguard")
    assert "address=/a.com/0.0.0.0" in render(doms, "dnsmasq")
    # domains sorted
    body = [l for l in render(doms, "domains").splitlines() if l and not l.startswith("#")]
    assert body == ["a.com", "b.com"]
