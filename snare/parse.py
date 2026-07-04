"""Parse any blocklist format into a normalized set of domains.

Handles the three formats blocklists ship in:
- hosts:   `0.0.0.0 example.com`  /  `127.0.0.1 example.com`
- adblock: `||example.com^`  (network domain-anchored rules; cosmetic/regex rules skipped)
- domains: `example.com` one per line
"""

from __future__ import annotations

import re

_HOSTS_IP = ("0.0.0.0", "127.0.0.1", "::", "::1")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9]+)*\.)+[a-z]{2,}$")
_ADBLOCK_DOMAIN = re.compile(r"^\|\|([a-z0-9.\-\*]+)\^?")


def _text(content):
    return content.decode("utf-8", "replace") if isinstance(content, (bytes, bytearray)) else content


def _valid(domain: str) -> bool:
    domain = domain.strip(".").lower()
    return bool(_DOMAIN_RE.match(domain)) and "*" not in domain


def _norm(domain: str):
    d = domain.strip().strip(".").lower()
    if d.startswith("www."):
        d = d[4:]
    return d


def parse(content, fmt: str = "auto") -> set:
    out = set()
    for raw in _text(content).splitlines():
        line = raw.strip()
        if not line or line[0] in "#!":            # comments (# hosts, ! adblock)
            continue
        if fmt in ("hosts", "auto") and line.split(" ")[0] in _HOSTS_IP:
            parts = line.split()
            for tok in parts[1:]:
                if tok.startswith("#"):
                    break
                if _valid(tok):
                    out.add(_norm(tok))
            continue
        if fmt in ("adblock", "auto") and line.startswith("||"):
            m = _ADBLOCK_DOMAIN.match(line)
            # skip rules with options that aren't pure blocks (e.g. $csp, ##) -> keep simple domain blocks
            if m and "$" not in line and "##" not in line:
                d = m.group(1)
                if _valid(d):
                    out.add(_norm(d))
            continue
        if fmt in ("domains", "auto"):
            tok = line.split()[0]
            if _valid(tok):
                out.add(_norm(tok))
    return out
