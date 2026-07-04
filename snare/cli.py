"""Snare CLI."""

from __future__ import annotations

import argparse
import sys

import json
import os

from . import __version__, qlog
from . import resolver as resolvermod
from .catalog import CATALOG
from .client import HttpClient
from .compile import FORMATS, build_blockmap, merge, render
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


def _blockmap(client, sources):
    tagged = []
    for s in sources:
        try:
            tagged.append((parse(client.get(s["url"]), s["fmt"]), s["category"]))
        except Exception:
            continue
    return build_blockmap(tagged)


def cmd_map(args):
    client = HttpClient(cache_dir=args.cache, offline=args.offline)
    bm = _blockmap(client, _select(args.categories, args.sources))
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(bm, f)
    from collections import Counter
    print(f"[+] blockmap: {len(bm):,} domains -> {args.out}")
    print("   by category:", dict(Counter(bm.values())))
    return 0


def cmd_resolve(args):
    if args.blockmap and os.path.exists(args.blockmap):
        with open(args.blockmap, "r", encoding="utf-8") as f:
            bm = json.load(f)
    else:
        print("[snare] no --blockmap; building live from sources (use `snare map` to cache)...")
        bm = _blockmap(HttpClient(cache_dir=args.cache, offline=args.offline),
                       _select(args.categories, None))
    resolvermod.serve(bm, host=args.host, port=args.port, upstream=args.upstream,
                      sinkhole=args.sinkhole, log_path=args.log)
    return 0


def cmd_log(args):
    for e in qlog.load(args.log or qlog.DEFAULT_LOG, limit=args.n):
        mark = "BLOCK" if e.get("action") == "block" else "allow"
        print(f"{e.get('ts','')}  {mark:5}  {e.get('label',''):18}  {e.get('domain','')}")
    return 0


def cmd_report(args):
    rep = qlog.report(qlog.load(args.log or qlog.DEFAULT_LOG))
    print(json.dumps(rep, indent=2))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="snare",
                                description="Snare — DNS ad/tracker/scam blocker + traffic labeler")
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

    m = sub.add_parser("map", help="compile a domain->category blockmap (for the resolver)")
    m.add_argument("--out", default="blockmap.json")
    m.add_argument("--categories")
    m.add_argument("--sources")
    m.add_argument("--offline", action="store_true")
    m.add_argument("--cache", default=".cache")
    m.set_defaults(func=cmd_map)

    r = sub.add_parser("resolve", help="run the filtering DNS resolver (AdGuard/NextDNS-style)")
    r.add_argument("--blockmap", help="blockmap.json from `snare map` (else builds live)")
    r.add_argument("--host", default="127.0.0.1")
    r.add_argument("--port", type=int, default=5353)
    r.add_argument("--upstream", default="1.1.1.1")
    r.add_argument("--sinkhole", default="0.0.0.0")
    r.add_argument("--categories")
    r.add_argument("--log")
    r.add_argument("--offline", action="store_true")
    r.add_argument("--cache", default=".cache")
    r.set_defaults(func=cmd_resolve)

    lg = sub.add_parser("log", help="show recent DNS decisions")
    lg.add_argument("-n", type=int, default=40)
    lg.add_argument("--log")
    lg.set_defaults(func=cmd_log)

    rp = sub.add_parser("report", help="traffic analytics over the query log")
    rp.add_argument("--log")
    rp.set_defaults(func=cmd_report)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
