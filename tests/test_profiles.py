from snare import dnswire
from snare.resolver import SnareResolver


def _fake(query, up):
    _, qt, qe = dnswire.parse_question(query)
    return dnswire.build_response(query, qe, qt, sinkhole="9.9.9.9")


def test_profile_blocks_label_for_client():
    # kids device (10.0.0.5) blocks the "social" label even though it's not on the blocklist
    profiles = {"10.0.0.5": {"block_labels": ["social"]}}
    r = SnareResolver({}, forwarder=_fake, profiles=profiles)
    # facebook -> heuristic label "social" -> blocked for this client
    resp = r.handle_query(dnswire.build_query("facebook.com"), "10.0.0.5")
    assert dnswire.answer_ip(resp) == "0.0.0.0"
    # a different client is unaffected -> forwarded
    resp2 = r.handle_query(dnswire.build_query("facebook.com"), "10.0.0.9")
    assert dnswire.answer_ip(resp2) == "9.9.9.9"


def test_profile_allow_overrides_blocklist():
    profiles = {"10.0.0.5": {"allow": ["ads.example"]}}
    r = SnareResolver({"ads.example": "ads"}, forwarder=_fake, profiles=profiles)
    resp = r.handle_query(dnswire.build_query("ads.example"), "10.0.0.5")
    assert dnswire.answer_ip(resp) == "9.9.9.9"  # allowed for this client


def test_wildcard_profile_applies_to_all():
    r = SnareResolver({}, forwarder=_fake, profiles={"*": {"block_labels": ["advertising"]}})
    resp = r.handle_query(dnswire.build_query("ads.doubleclick.net"), "1.2.3.4")
    assert dnswire.answer_ip(resp) == "0.0.0.0"
