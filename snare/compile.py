"""Compile a normalized domain set into the output format a client wants."""

from __future__ import annotations

FORMATS = ("hosts", "domains", "adguard", "dnsmasq")


def render(domains, fmt: str = "hosts", sinkhole: str = "0.0.0.0", title: str = "Snare") -> str:
    doms = sorted(domains)
    header = [f"! Title: {title}", f"! Entries: {len(doms)}",
              "! Aggregated from public blocklists — see NOTICE for sources & licenses.", ""]
    if fmt == "hosts":
        header = [h.replace("! ", "# ") for h in header]
        body = [f"{sinkhole} {d}" for d in doms]
    elif fmt == "domains":
        header = [h.replace("! ", "# ") for h in header]
        body = list(doms)
    elif fmt == "adguard":
        body = [f"||{d}^" for d in doms]
    elif fmt == "dnsmasq":
        header = [h.replace("! ", "# ") for h in header]
        body = [f"address=/{d}/{sinkhole}" for d in doms]
    else:
        raise ValueError(f"unknown format: {fmt} (use one of {FORMATS})")
    return "\n".join(header + body) + "\n"


def merge(domain_sets) -> set:
    out = set()
    for s in domain_sets:
        out |= s
    return out
