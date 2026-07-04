"""Snare — browser threat & ad/scam blocklist aggregator.

Pulls the major public blocklists (AdGuard family, ad/tracker lists, malware &
phishing/scam feeds, and anti-malvertising / malicious-redirect lists),
normalizes them from any format (hosts / AdBlock-syntax / plain domains), dedupes,
and compiles a single blocklist in the format your browser or DNS wants
(hosts, plain domains, AdGuard/uBlock syntax, or dnsmasq).

Keyless and offline-capable (fetches cache to disk). It aggregates third-party
lists under their own licenses — see NOTICE.
"""

__version__ = "0.3.0"
__all__ = ["catalog", "client", "parse", "compile", "cli"]
