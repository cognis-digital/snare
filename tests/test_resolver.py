import os

from snare import dnswire, labels, qlog
from snare.resolver import SnareResolver


def test_dns_query_roundtrip():
    q = dnswire.build_query("ads.example.com", dnswire.TYPE_A)
    name, qtype, qend = dnswire.parse_question(q)
    assert name == "ads.example.com" and qtype == dnswire.TYPE_A
    resp = dnswire.build_response(q, qend, qtype, sinkhole="0.0.0.0")
    assert dnswire.txn_id(resp) == dnswire.txn_id(q)
    assert dnswire.answer_ip(resp) == "0.0.0.0"


def test_aaaa_block_is_nodata():
    q = dnswire.build_query("ads.example.com", dnswire.TYPE_AAAA)
    _, qtype, qend = dnswire.parse_question(q)
    resp = dnswire.build_response(q, qend, qtype)
    # NODATA: no answers, no IP handed out
    assert dnswire.answer_ip(resp) is None


def test_labels_block_and_heuristic():
    bm = {"ads.example.com": "ads"}
    c = labels.classify("sub.ads.example.com", bm)      # parent-domain match
    assert c["blocked"] and c["block_category"] == "ads"
    assert labels.classify("www.google-analytics.com")["label"] == "tracking-analytics"
    assert labels.classify("example.org")["label"] == "uncategorized"


def test_resolver_blocks_and_allows(tmp_path):
    log = str(tmp_path / "q.jsonl")
    # fake upstream that returns a canned A=1.2.3.4 answer
    def fake_forward(query, upstream):
        _, qtype, qend = dnswire.parse_question(query)
        return dnswire.build_response(query, qend, qtype, sinkhole="1.2.3.4")
    r = SnareResolver({"tracker.bad": "tracking"}, log_path=log, forwarder=fake_forward)

    blocked = r.handle_query(dnswire.build_query("tracker.bad"), "10.0.0.9")
    assert dnswire.answer_ip(blocked) == "0.0.0.0"          # sinkholed

    allowed = r.handle_query(dnswire.build_query("good.example"), "10.0.0.9")
    assert dnswire.answer_ip(allowed) == "1.2.3.4"          # forwarded

    rep = qlog.report(qlog.load(log))
    assert rep["total"] == 2 and rep["blocked"] == 1 and rep["allowed"] == 1
    assert rep["block_rate"] == 0.5
    assert "tracker.bad" in rep["top_blocked"]


def test_report_shape():
    entries = [{"action": "block", "domain": "a.ads", "label": "ads", "block_category": "ads", "client": "x"},
               {"action": "allow", "domain": "b.io", "label": "uncategorized", "client": "x"}]
    rep = qlog.report(entries)
    assert rep["by_label"]["ads"] == 1 and rep["by_block_category"]["ads"] == 1
