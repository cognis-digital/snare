"""Catalog of public blocklists (all keyless).

category: adguard | ads | tracking | malware | phishing-scam | redirect-malvertising
fmt:      hosts | adblock | domains   (source native format, for the parser)
license:  upstream license (respected on aggregation — see NOTICE)
"""

from __future__ import annotations

_RAW = [
    # name, category, url, fmt, license
    # ---- AdGuard family ----
    ("adguard_base", "adguard", "https://filters.adtidy.org/extension/ublock/filters/2.txt", "adblock", "GPLv3"),
    ("adguard_tracking", "adguard", "https://filters.adtidy.org/extension/ublock/filters/3.txt", "adblock", "GPLv3"),
    ("adguard_social", "adguard", "https://filters.adtidy.org/extension/ublock/filters/4.txt", "adblock", "GPLv3"),
    ("adguard_annoyances", "adguard", "https://filters.adtidy.org/extension/ublock/filters/14.txt", "adblock", "GPLv3"),
    ("adguard_mobile_ads", "adguard", "https://filters.adtidy.org/extension/ublock/filters/11.txt", "adblock", "GPLv3"),
    ("adguard_dns", "adguard", "https://raw.githubusercontent.com/AdguardTeam/AdguardSDNSFilter/master/Filters/filter.txt", "adblock", "GPLv3"),
    # ---- Ads / trackers ----
    ("easylist", "ads", "https://easylist.to/easylist/easylist.txt", "adblock", "GPLv3/CC-BY-SA"),
    ("easyprivacy", "tracking", "https://easylist.to/easylist/easyprivacy.txt", "adblock", "GPLv3/CC-BY-SA"),
    ("peter_lowe", "ads", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext", "hosts", "custom-free"),
    ("stevenblack_unified", "ads", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "hosts", "MIT"),
    # ---- Malware ----
    ("urlhaus_hosts", "malware", "https://urlhaus.abuse.ch/downloads/hostfile/", "hosts", "CC0"),
    ("adguard_malware_dns", "malware", "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets/filter_9.txt", "adblock", "GPLv3"),
    ("disconnect_malvertising", "malware", "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt", "domains", "GPLv3"),
    ("digitalside_threat", "malware", "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt", "domains", "CC-BY-4.0"),
    # ---- Phishing / scam ----
    ("phishing_army", "phishing-scam", "https://phishing.army/download/phishing_army_blocklist_extended.txt", "domains", "custom-free"),
    ("scamblocklist_durablenapkin", "phishing-scam", "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt", "hosts", "MIT"),
    ("oisd_nsfw_small", "phishing-scam", "https://small.oisd.nl", "domains", "custom-free"),
    ("phishtank_online", "phishing-scam", "http://data.phishtank.com/data/online-valid.csv", "domains", "custom-free"),
    # ---- Redirect / malvertising / crypto-jacking ----
    ("nocoin", "redirect-malvertising", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", "hosts", "MIT"),
    ("frellwits_annoyance", "redirect-malvertising", "https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Filter.txt", "adblock", "CC-BY-SA"),
    ("ublock_badware", "redirect-malvertising", "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt", "adblock", "GPLv3"),
    ("ublock_privacy", "tracking", "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt", "adblock", "GPLv3"),
    ("hagezi_tif", "malware", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt", "domains", "GPLv3"),
    ("hagezi_multi", "ads", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt", "domains", "GPLv3"),
]

CATALOG = [
    {"name": n, "category": c, "url": u, "fmt": f, "license": lic}
    for (n, c, u, f, lic) in _RAW
]
