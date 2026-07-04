from snare import analytics, dga, pkg


def test_dga_flags_random_domain_and_clears_real_ones():
    assert dga.score("kq3v9xzp2wjfh.com")["suspicious"] is True
    for good in ("google.com", "microsoft.com", "wikipedia.org", "cognis.digital"):
        assert dga.score(good)["suspicious"] is False, good


def test_dga_ignores_short_labels():
    r = dga.score("bit.ly")
    assert r["suspicious"] is False


def _log():
    return [
        {"ts": "2026-07-04T10:00:01", "client": "10.0.0.5", "domain": "ads.doubleclick.net",
         "action": "block", "label": "advertising"},
        {"ts": "2026-07-04T10:00:02", "client": "10.0.0.5", "domain": "google.com",
         "action": "allow", "label": "uncategorized"},
        {"ts": "2026-07-04T11:00:00", "client": "10.0.0.9", "domain": "kq3v9xzp2wjfh.com",
         "action": "allow", "label": "uncategorized"},
    ]


def test_timeseries_buckets_by_hour():
    ts = analytics.timeseries(_log())
    assert ts["2026-07-04T10"] == {"total": 2, "blocked": 1}
    assert ts["2026-07-04T11"]["total"] == 1


def test_per_client_block_rate():
    pc = analytics.per_client(_log())
    assert pc["10.0.0.5"]["total"] == 2
    assert pc["10.0.0.5"]["blocked"] == 1
    assert pc["10.0.0.5"]["block_rate"] == 0.5


def test_dga_suspects_surface_from_log():
    sus = analytics.dga_suspects(_log())
    assert any(s["domain"] == "kq3v9xzp2wjfh.com" for s in sus)


def test_rare_domains():
    rare = analytics.rare_domains(_log(), max_count=1)
    assert "kq3v9xzp2wjfh.com" in rare


def test_full_report_has_sections():
    rep = analytics.full(_log())
    for k in ("hourly", "per_client", "rare_domains", "dga_suspects"):
        assert k in rep


def test_pkg_adguard_filter_and_managed():
    doms = {"ads.example", "track.example"}
    f = pkg.adguard_filter(doms)
    assert "||ads.example^" in f and "! Title: Snare" in f
    m = pkg.ublock_managed(doms)
    assert "adminSettings" in m and "||track.example^" in m["adminSettings"]


def test_pkg_dnr_ruleset_shape_and_cap():
    doms = {f"d{i}.example" for i in range(5)}
    rules, dropped = pkg.dnr_ruleset(doms)
    assert dropped == 0 and len(rules) == 5
    assert rules[0]["action"]["type"] == "block"
    rules2, dropped2 = pkg.dnr_ruleset(doms, limit=2)
    assert len(rules2) == 2 and dropped2 == 3


def test_pkg_extension_bundle(tmp_path):
    res = pkg.extension_bundle({"ads.example"}, str(tmp_path / "ext"))
    assert res["rules"] == 1
    assert (tmp_path / "ext" / "manifest.json").exists()
    assert (tmp_path / "ext" / "rules.json").exists()
