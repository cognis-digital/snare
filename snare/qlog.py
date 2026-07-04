"""Query log — append-only JSONL of every DNS decision, and a report over it.

This is the "studies traffic" half: every query is recorded with its decision and
label so `snare report` can show what a network is actually doing (top blocked,
category breakdown, block rate, top talkers) — NextDNS-style analytics, local.
"""

from __future__ import annotations

import json
import os
from collections import Counter

DEFAULT_LOG = os.path.join(os.path.expanduser("~"), ".snare", "queries.jsonl")


def append(entry: dict, path: str = DEFAULT_LOG) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load(path: str = DEFAULT_LOG, limit: int = 0) -> list:
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows[-limit:] if limit else rows


def report(entries: list, top: int = 10) -> dict:
    total = len(entries)
    blocked = [e for e in entries if e.get("action") == "block"]
    allowed = [e for e in entries if e.get("action") == "allow"]
    return {
        "total": total,
        "blocked": len(blocked),
        "allowed": len(allowed),
        "block_rate": round(len(blocked) / total, 4) if total else 0.0,
        "by_label": dict(Counter(e.get("label", "uncategorized") for e in entries).most_common()),
        "by_block_category": dict(Counter(e.get("block_category") for e in blocked
                                          if e.get("block_category")).most_common()),
        "top_blocked": [d for d, _ in Counter(e.get("domain") for e in blocked).most_common(top)],
        "top_allowed": [d for d, _ in Counter(e.get("domain") for e in allowed).most_common(top)],
        "top_clients": dict(Counter(e.get("client", "?") for e in entries).most_common(top)),
    }
