"""Snare CLI."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .catalog import CATALOG
from .client import HttpClient
from .compile import FORMATS, merge, render
from .parse import parse

_BY_NAME = {s["name"]: s for s in CATALOG}


def _select(categories, names):
    sel = CATALOG
    if categories:
        cats = set(categories.split(","))
        sel = [s for s in sel if s["category"] in cats]
    if names:
        want = set(names.split(","))
        sel = [s for s in sel if s["name"] in want]
    return sel


def cmd_sources(args):
    for s in CATALOG:
        print(f"{s['name']:28} {s['category']:22} {s['fmt']:8} {s['license']}")
    cats = sorted({s['category'] for s in CATALOG})
    print(f"\n{len(CATALOG)} lists · categories: {', '.join(cats)}")
    return 0


def cmd_build(args):
    client = HttpClient(cache_dir=args.cache, offline=args.offline)
    sources = _select(args.categories, args.sources)
    sets, errors, per = [], {}, []
    for s in sources:
        try:
            d = parse(client.get(s["url"]), s["fmt"])
            sets.append(d)
            per.append((s["name"], len(d)))
        except Exception as e:
            errors[s["name"]] = str(e)
    domains = merge(sets)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(render(domains, args.format))
        print(f"[+] {len(domains):,} unique domains -> {args.out} ({args.format})")
    else:
        print(render(domains, args.format))
    for n, c in sorted(per, key=lambda x: -x[1])[:12]:
        print(f"   {n:28} {c:>8,}", file=sys.stderr)
    if errors:
        print(f"   [!] {len(errors)} sources failed: {', '.join(errors)}", file=sys.stderr)
    return 0


def cmd_stats(args):
    from collections import Counter
    c = Counter(s["category"] for s in CATALOG)
    print({"lists": len(CATALOG), "by_category": dict(sorted(c.items())),
           "formats": sorted({s['fmt'] for s in CATALOG})})
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="snare",
                                description="Snare — browser blocklist aggregator")
    p.add_argument("--version", action="version", version=f"snare {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("sources", help="list aggregated blocklists")
    s.set_defaults(func=cmd_sources)

    st = sub.add_parser("stats", help="coverage stats")
    st.set_defaults(func=cmd_stats)

    b = sub.add_parser("build", help="fetch + merge + compile a blocklist")
    b.add_argument("--format", choices=FORMATS, default="hosts")
    b.add_argument("--categories", help="comma list (e.g. malware,phishing-scam)")
    b.add_argument("--sources", help="comma list of source names")
    b.add_argument("--out", help="output path (else stdout)")
    b.add_argument("--offline", action="store_true")
    b.add_argument("--cache", default=".cache")
    b.set_defaults(func=cmd_build)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
