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
    # ---- massively expanded set (all keyless public lists) ----
    ("hagezi_light", "ads", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt", "domains", "GPLv3"),
    ("hagezi_pro", "ads", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt", "domains", "GPLv3"),
    ("hagezi_proplus", "ads", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.plus.txt", "domains", "GPLv3"),
    ("hagezi_fake", "phishing-scam", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/fake.txt", "domains", "GPLv3"),
    ("hagezi_popupads", "ads", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/popupads.txt", "domains", "GPLv3"),
    ("hagezi_native_amazon", "tracking", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.amazon.txt", "domains", "GPLv3"),
    ("hagezi_native_apple", "tracking", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.apple.txt", "domains", "GPLv3"),
    ("hagezi_native_winoffice", "tracking", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.winoffice.txt", "domains", "GPLv3"),
    ("hagezi_native_tiktok", "tracking", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.tiktok.txt", "domains", "GPLv3"),
    ("hagezi_doh", "tracking", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/doh.txt", "domains", "GPLv3"),
    ("onehosts_lite", "ads", "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt", "domains", "custom-free"),
    ("onehosts_pro", "ads", "https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/domains.txt", "domains", "custom-free"),
    ("oisd_big", "ads", "https://big.oisd.nl/domainswild", "domains", "custom-free"),
    ("oisd_nsfw", "phishing-scam", "https://nsfw.oisd.nl/domainswild", "domains", "custom-free"),
    ("someonewhocares", "ads", "https://someonewhocares.org/hosts/zero/hosts", "hosts", "custom-free"),
    ("adaway", "ads", "https://adaway.org/hosts.txt", "hosts", "CC-BY-3.0"),
    ("dandelionsprout_antimalware", "malware", "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt", "hosts", "custom-free"),
    ("developerdan_ads", "ads", "https://raw.githubusercontent.com/lightswitch05/dns-blocklists/master/lists/ads-and-tracking-extended.txt", "domains", "custom-free"),
    ("notracking", "tracking", "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt", "hosts", "custom-free"),
    ("shadowwhisperer_ads", "ads", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Ads", "domains", "MIT"),
    ("shadowwhisperer_malware", "malware", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Malware", "domains", "MIT"),
    ("shadowwhisperer_scam", "phishing-scam", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Scam", "domains", "MIT"),
    ("frogeye_firstparty", "tracking", "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt", "hosts", "custom-free"),
    ("frogeye_multiparty", "tracking", "https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt", "hosts", "custom-free"),
    ("adguard_cname_trackers", "tracking", "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers_justdomains.txt", "domains", "GPLv3"),
    ("adguard_url_tracking", "tracking", "https://filters.adtidy.org/extension/ublock/filters/17.txt", "adblock", "GPLv3"),
    ("ublock_resource_abuse", "redirect-malvertising", "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt", "adblock", "GPLv3"),
    ("ublock_quick_fixes", "ads", "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/quick-fixes.txt", "adblock", "GPLv3"),
    ("fanboy_annoyance", "ads", "https://secure.fanboy.co.nz/fanboy-annoyance.txt", "adblock", "CC-BY-SA"),
    ("fanboy_social", "ads", "https://secure.fanboy.co.nz/fanboy-social.txt", "adblock", "CC-BY-SA"),
    ("easylist_cookie", "ads", "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt", "adblock", "CC-BY-SA"),
    ("crazymax_spy", "tracking", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", "hosts", "MIT"),
    ("perflyst_smarttv", "tracking", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt", "domains", "custom-free"),
    ("perflyst_android", "tracking", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt", "domains", "custom-free"),
    ("malwareworld_urlhaus", "malware", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt", "hosts", "custom-free"),
    ("phishing_db_active", "phishing-scam", "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", "domains", "custom-free"),
    ("spam404", "phishing-scam", "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt", "domains", "custom-free"),
    ("kadhosts", "ads", "https://raw.githubusercontent.com/FiltersHeroes/KADhosts/master/KADhosts.txt", "hosts", "CC-BY-SA"),
    ("cryptojacking_hosts", "redirect-malvertising", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", "hosts", "MIT"),
]

CATALOG = [
    {"name": n, "category": c, "url": u, "fmt": f, "license": lic}
    for (n, c, u, f, lic) in _RAW
]
