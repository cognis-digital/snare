"""DGA (domain-generation-algorithm) suspicion scoring.

Malware C2 often uses algorithmically-generated domains (high-entropy, vowel-poor,
digit-heavy random strings like `kq3v9xzp2wjf.com`). This flags them so Snare can
surface likely-malicious lookups even when they're not yet on any blocklist — a
real hunt signal. Pure heuristic, no network, no ML weights to ship.
"""

from __future__ import annotations

import math
import re
from collections import Counter

_CONSONANT_RUN = re.compile(r"[bcdfghjklmnpqrstvwxyz]+")
_VOWELS = set("aeiou")
# common legitimate multi-part TLDs so we score the right label
_MULTI_TLD = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk", "gov.uk", "ac.uk"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def registrable_label(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_TLD:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def score(domain: str) -> dict:
    label = "".join(ch for ch in registrable_label(domain) if ch.isalnum())
    if len(label) < 7:  # short names are rarely DGA; avoid false positives
        return {"domain": domain, "label": label, "score": 0.0, "suspicious": False,
                "entropy": round(_entropy(label), 2), "reason": "too short"}
    ent = _entropy(label)
    digits = sum(c.isdigit() for c in label) / len(label)
    vowels = sum(c in _VOWELS for c in label) / len(label)
    max_run = max((len(m) for m in _CONSONANT_RUN.findall(label)), default=0)
    s = (0.35 * min(1.0, max(0.0, ent - 3.0) / 1.5)
         + 0.20 * min(1.0, digits / 0.30)
         + 0.20 * min(1.0, max(0.0, 0.32 - vowels) / 0.32)
         + 0.15 * min(1.0, max_run / 5.0)
         + 0.10 * min(1.0, max(0.0, len(label) - 12) / 8.0))
    s = round(max(0.0, min(1.0, s)), 3)
    return {"domain": domain, "label": label, "score": s, "suspicious": s >= 0.6,
            "entropy": round(ent, 2), "digit_ratio": round(digits, 2),
            "vowel_ratio": round(vowels, 2), "max_consonant_run": max_run}
