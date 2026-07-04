<h1 align="center">🟣 Snare</h1>
<p align="center"><b>Self-hosted DNS ad/tracker/scam blocker that listens, studies &amp; labels your traffic.</b><br>
<i>An AdGuard + NextDNS replacement you own: a filtering DNS resolver over 24 aggregated blocklists, with a query log and traffic analytics — keyless, offline-capable, zero-dependency.</i></p>

<p align="center">
<img alt="license" src="https://img.shields.io/badge/license-COCL--1.0-6D28D9">
<img alt="python" src="https://img.shields.io/badge/python-3.9%2B-6D28D9">
<img alt="deps" src="https://img.shields.io/badge/dependencies-none%20(stdlib)-6D28D9">
<img alt="lists" src="https://img.shields.io/badge/sources-24%20lists-6D28D9">
</p>

---

Snare pulls the big public blocklists — **AdGuard** (Base, Tracking, Social,
Annoyances, Mobile, DNS), **EasyList/EasyPrivacy**, **StevenBlack**, **uBlock**
filters, **abuse.ch URLhaus**, **hagezi**, **OISD**, **Phishing Army**,
**Disconnect malvertising**, anti-crypto-jacking, scam lists, and more — parses
whatever format each ships in, **dedupes into one set**, and compiles it for
your client. Millions of domains, one command.

> **What it blocks:** ads, trackers, malware/phishing/scam domains, and the
> malvertising / malicious-redirect infrastructure behind browser redirect attacks.
> **Where it works:** any browser via uBlock Origin / AdGuard, or network-wide via
> a hosts file, Pi-hole, AdGuard Home, or dnsmasq.

## Run it as your resolver (AdGuard / NextDNS replacement)

```bash
git clone https://github.com/cognis-digital/snare
cd snare
python -m snare map --out blockmap.json                 # compile domain->category map (once)
python -m snare resolve --blockmap blockmap.json --port 5353
#   → point your OS / router / browser DNS at 127.0.0.1:5353
python -m snare report                                  # traffic analytics (NextDNS-style)
python -m snare log -n 40                               # recent decisions
```

The resolver **listens** for DNS queries, **blocks** ads/trackers/scam/malware/
redirect domains (sinkhole → 0.0.0.0, or NODATA), **forwards** everything else to
an upstream (default 1.1.1.1), and **labels + logs** every query — so `snare report`
shows block rate, category breakdown, top blocked/allowed domains, and top talkers.
Parent-domain matching means `ads.doubleclick.net` is caught by `doubleclick.net`.

## Or just compile a blocklist file

```bash
python -m snare sources                                   # list the 24 lists
python -m snare build --format hosts --out snare.hosts    # everything -> hosts file
python -m snare build --categories malware,phishing-scam --format adguard --out snare.txt
python -m snare build --format dnsmasq --out snare.conf   # for dnsmasq / Pi-hole
```

Formats: **hosts** (`0.0.0.0 domain`), **domains** (plain), **adguard** (`||domain^`,
for uBlock/AdGuard), **dnsmasq** (`address=/domain/0.0.0.0`). Filter by
`--categories` (`adguard, ads, tracking, malware, phishing-scam, redirect-malvertising`)
or `--sources`. Add `--offline --cache DIR` to rebuild from a cached snapshot.

## How it works

- **Fetch** (keyless, cached) → **parse** (hosts / AdBlock-syntax / plain domains
  all normalized to bare domains) → **merge/dedupe** → **compile** to your format.
- Zero dependencies (Python stdlib), so it runs air-gapped from a cached snapshot.

## Honest notes

Snare **aggregates** third-party lists; it does not host them. Each upstream list
keeps its own license — if you redistribute a compiled output, comply with the
most restrictive upstream license (GPLv3 / CC BY-SA share-alike). See
[NOTICE](NOTICE). "Blocks redirect attacks" means it aggregates the leading
anti-malvertising / malicious-redirect / scam lists — no blocklist is exhaustive.

## Testing

```bash
python -m pytest -q      # parser / merge / compile / catalog gates
```

## License

Snare's code is source-available under **COCL v1.0** (see [LICENSE](LICENSE)).

<p align="center"><sub>© 2026 Cognis Digital LLC · <a href="https://cognis.digital">cognis.digital</a></sub></p>
