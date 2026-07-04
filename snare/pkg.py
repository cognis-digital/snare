"""Browser-extension & managed-deployment packaging.

Turns a compiled blocklist into artifacts you can actually load or push to a fleet:

  * adguard_filter   — importable custom filter (uBlock Origin / AdGuard / Brave)
  * ublock_managed   — uBlock Origin enterprise managed-storage config (force-apply
                       filters across a managed fleet, no user action)
  * dnr_ruleset      — Chrome/Edge Manifest V3 declarativeNetRequest rules
  * extension_bundle — writes a complete, load-unpacked MV3 extension directory

All pure stdlib; deterministic (sorted) output.
"""

from __future__ import annotations

import json
import os

# Chrome caps enabled static DNR rules; keep well under the guaranteed minimum.
DNR_LIMIT = 30000

_MANIFEST = {
    "manifest_version": 3,
    "name": "Snare — ad/tracker/scam blocker",
    "version": "1.0.0",
    "description": "Blocks ads, trackers, telemetry, scam & malware domains. By Cognis Digital.",
    "permissions": ["declarativeNetRequest"],
    "declarative_net_request": {
        "rule_resources": [{
            "id": "snare_ruleset",
            "enabled": True,
            "path": "rules.json",
        }]
    },
}


def adguard_filter(domains, title: str = "Snare") -> str:
    from . import __version__
    doms = sorted(domains)
    head = [f"! Title: {title}",
            "! Description: Aggregated ad/tracker/scam/malware blocklist — Cognis Digital",
            f"! Version: {__version__}", f"! Entries: {len(doms)}",
            "! Homepage: https://github.com/cognis-digital/snare",
            "! License: see NOTICE (aggregated third-party lists under their own licenses)", ""]
    return "\n".join(head + [f"||{d}^" for d in doms]) + "\n"


def ublock_managed(domains, title: str = "Snare") -> dict:
    """uBlock Origin managed-storage config. Deploy via the platform's managed
    policy for uBO (chrome extension id `cjpalhdlnbpafiamejdnhcphjbkeiagm`):
    put this object at that key so filters apply fleet-wide with no user action."""
    admin = {"userFilters": "\n".join(f"||{d}^" for d in sorted(domains))}
    return {"name": title, "adminSettings": json.dumps(admin, separators=(",", ":"))}


def dnr_ruleset(domains, limit: int = DNR_LIMIT) -> tuple:
    """Chrome/Edge MV3 declarativeNetRequest rules. Returns (rules, dropped)."""
    doms = sorted(domains)
    kept, dropped = doms[:limit], max(0, len(doms) - limit)
    rules = [{"id": i + 1, "priority": 1, "action": {"type": "block"},
              "condition": {"urlFilter": f"||{d}^",
                            "resourceTypes": ["main_frame", "sub_frame", "script", "image",
                                              "xmlhttprequest", "stylesheet", "font", "media",
                                              "websocket", "ping", "object", "other"]}}
             for i, d in enumerate(kept)]
    return rules, dropped


def extension_bundle(domains, outdir: str, title: str = "Snare") -> dict:
    """Write a complete load-unpacked MV3 extension into `outdir`."""
    os.makedirs(outdir, exist_ok=True)
    rules, dropped = dnr_ruleset(domains)
    manifest = dict(_MANIFEST, name=title)
    with open(os.path.join(outdir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    with open(os.path.join(outdir, "rules.json"), "w", encoding="utf-8") as f:
        json.dump(rules, f)
    readme = (f"# {title} browser extension (Manifest V3)\n\n"
              f"{len(rules):,} block rules"
              + (f" ({dropped:,} domains dropped — over the {DNR_LIMIT:,} static-rule cap;\n"
                 "  split into multiple rulesets or pair with the Snare DNS resolver for full coverage)\n"
                 if dropped else "\n")
              + "\n## Load it\n"
                "- **Chrome/Edge:** chrome://extensions → enable Developer mode → "
                "Load unpacked → select this folder.\n"
                "- **Firefox:** use the AdGuard-format filter (`snare export --target adguard`) "
                "imported into uBlock Origin instead (Firefox MV3 DNR differs).\n\n"
                "Built by Snare — Cognis Digital · https://github.com/cognis-digital/snare\n")
    with open(os.path.join(outdir, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)
    return {"dir": outdir, "rules": len(rules), "dropped": dropped}
