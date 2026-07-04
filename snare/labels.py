"""Traffic labeling — categorize a domain so Snare can *study* traffic, not just
block it.

Two layers:
1. Blocklist category: if the domain is on a compiled list, it inherits that
   list's category (ads / tracking / malware / phishing-scam / redirect-malvertising).
2. Heuristic label: for ALL traffic (allowed included), keyword rules bucket the
   domain into advertising / tracking-analytics / telemetry / social / cdn-infra /
   malware-scam / uncategorized — so the report shows what a device is really doing.
"""

from __future__ import annotations

_HEURISTICS = [
    ("advertising", ("ads", "adservice", "adserver", "doubleclick", "googlesyndication",
                     "adnxs", "adsystem", "advertising", "pubmatic", "rubiconproject",
                     "taboola", "outbrain", "criteo", "moatads", "banner")),
    ("tracking-analytics", ("analytics", "track", "tracker", "metric", "telemetry.js",
                            "segment", "mixpanel", "amplitude", "hotjar", "fullstory",
                            "scorecardresearch", "quantserve", "chartbeat", "newrelic",
                            "google-analytics", "googletagmanager", "pixel", "beacon")),
    ("telemetry", ("telemetry", "crashlytics", "sentry", "bugsnag", "app-measurement",
                   "settings-win.data.microsoft", "vortex.data.microsoft", "incoming.telemetry")),
    ("social", ("facebook", "fbcdn", "twitter", "t.co", "instagram", "tiktok",
                "linkedin", "snapchat", "reddit", "pinterest")),
    ("cdn-infra", ("cloudfront", "akamai", "fastly", "cdn", "amazonaws", "azureedge",
                   "cloudflare", "gstatic", "googleapis")),
]


def heuristic_label(domain: str) -> str:
    d = domain.lower()
    for label, needles in _HEURISTICS:
        if any(n in d for n in needles):
            return label
    return "uncategorized"


def classify(domain: str, blockmap: dict | None = None) -> dict:
    """Return {domain, blocked, block_category, label}.
    blockmap: optional {domain: source_category} from a compiled list."""
    bl = (blockmap or {})
    d = domain.lower().rstrip(".")
    cat = bl.get(d)
    # also match a parent domain (e.g. sub.ads.example -> ads.example blocked)
    if cat is None:
        parts = d.split(".")
        for k in range(1, len(parts) - 1):
            parent = ".".join(parts[k:])
            if parent in bl:
                cat = bl[parent]
                break
    return {"domain": d, "blocked": cat is not None,
            "block_category": cat, "label": cat or heuristic_label(d)}
