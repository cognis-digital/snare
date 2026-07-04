"""Rich analytics over the query log — the "great analytics" layer.

Beyond the basic block/allow report: hourly time-series, per-client breakdowns,
new/rare domain surfacing, and DGA-suspect lookups (likely malware C2 that isn't
on any list yet). All pure functions over qlog entries.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from . import dga


def timeseries(entries: list) -> dict:
    """Queries + blocks bucketed by hour (from the ISO 'ts' field, to the hour)."""
    buckets = defaultdict(lambda: {"total": 0, "blocked": 0})
    for e in entries:
        ts = str(e.get("ts", ""))
        hour = ts[:13]  # YYYY-MM-DDTHH
        if not hour:
            continue
        b = buckets[hour]
        b["total"] += 1
        if e.get("action") == "block":
            b["blocked"] += 1
    return dict(sorted(buckets.items()))


def per_client(entries: list, top: int = 10) -> dict:
    agg = defaultdict(lambda: {"total": 0, "blocked": 0, "labels": Counter()})
    for e in entries:
        c = e.get("client", "?")
        a = agg[c]
        a["total"] += 1
        if e.get("action") == "block":
            a["blocked"] += 1
        a["labels"][e.get("label", "uncategorized")] += 1
    out = {}
    for c, a in sorted(agg.items(), key=lambda kv: -kv[1]["total"])[:top]:
        out[c] = {"total": a["total"], "blocked": a["blocked"],
                  "block_rate": round(a["blocked"] / a["total"], 3) if a["total"] else 0.0,
                  "top_labels": dict(a["labels"].most_common(3))}
    return out


def rare_domains(entries: list, max_count: int = 1, limit: int = 25) -> list:
    """Domains seen very few times — rare lookups worth an analyst's eye."""
    counts = Counter(e.get("domain") for e in entries if e.get("domain"))
    return [d for d, n in counts.items() if n <= max_count][:limit]


def dga_suspects(entries: list, threshold: float = 0.6, limit: int = 25) -> list:
    """Distinct queried domains that look algorithmically generated (possible C2)."""
    seen = {}
    for e in entries:
        d = e.get("domain")
        if d and d not in seen:
            sc = dga.score(d)
            if sc["suspicious"] and sc["score"] >= threshold:
                seen[d] = {"domain": d, "score": sc["score"], "action": e.get("action")}
    return sorted(seen.values(), key=lambda x: -x["score"])[:limit]


def full(entries: list) -> dict:
    from . import qlog
    rep = qlog.report(entries)
    rep["hourly"] = timeseries(entries)
    rep["per_client"] = per_client(entries)
    rep["rare_domains"] = rare_domains(entries)
    rep["dga_suspects"] = dga_suspects(entries)
    return rep
