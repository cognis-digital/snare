from snare import dnswire, service, ui
from snare.catalog import CATALOG
from snare.resolver import SnareResolver


def test_catalog_massively_expanded():
    assert len(CATALOG) >= 60
    assert len({s["name"] for s in CATALOG}) == len(CATALOG)  # unique


def test_allowlist_overrides_block(tmp_path):
    log = str(tmp_path / "q.jsonl")

    def fake(query, up):
        _, qt, qe = dnswire.parse_question(query)
        return dnswire.build_response(query, qe, qt, sinkhole="9.9.9.9")

    r = SnareResolver({"ads.example": "ads"}, log_path=log, forwarder=fake,
                      allowlist={"ads.example"})
    # allowlisted -> forwarded, not sinkholed
    resp = r.handle_query(dnswire.build_query("ads.example"), "1.1.1.1")
    assert dnswire.answer_ip(resp) == "9.9.9.9"


def test_doh_forwarder_wired():
    r = SnareResolver({}, doh_url="https://cloudflare-dns.com/dns-query")
    # forwarder should be the DoH lambda, not plain UDP forward
    assert r.forward is not dnswire.forward
    assert "cloudflare" in dnswire.DOH_ENDPOINTS


def test_ui_render_is_selfcontained():
    rep = {"total": 3, "blocked": 1, "allowed": 2, "block_rate": 0.33,
           "by_label": {"ads": 1, "uncategorized": 2}, "by_block_category": {"ads": 1},
           "top_blocked": ["ads.example"], "top_allowed": ["good.io"], "top_clients": {"10.0.0.1": 3}}
    h = ui.render(rep, [{"ts": "t", "action": "block", "label": "ads", "domain": "ads.example"}])
    assert "<!doctype html>" in h.lower()
    assert "http://" not in h.split("</style>")[0]  # no external assets in the styled head
    assert "Cognis Digital" in h and "ads.example" in h


def test_service_generators():
    argv = ["/usr/bin/python", "-m", "snare", "resolve", "--port", "5353"]
    assert "ExecStart=" in service.systemd_unit(argv)
    assert "<plist" in service.launchd_plist(argv)
    assert "snare" in service.windows_cmd(argv)
