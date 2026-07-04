# Changelog

Adheres to [Semantic Versioning](https://semver.org/).

## [0.5.0] — 2026-07-04

### Added
- **Browser-extension packaging** (`snare export <target>`):
  - `extension` — writes a complete, load-unpacked **Manifest V3** extension
    (manifest.json + declarativeNetRequest rules.json + README) for Chrome/Edge.
  - `adguard` — importable custom filter list for uBlock Origin / AdGuard / Brave.
  - `dnr` — raw Chrome MV3 declarativeNetRequest ruleset (with static-rule-cap handling).
  - `ublock-managed` — uBlock Origin enterprise **managed-storage** config to force
    filters across a managed fleet with no user action.
- **DGA / malware-domain detection** (`dga.py`) — entropy + vowel/digit/consonant-run
  heuristic flags algorithmically-generated domains (likely C2) even when they're on
  no blocklist. Surfaced via `snare explain <domain>` and the dashboard.
- **Rich analytics** (`analytics.py`, `snare analytics`) — hourly time-series,
  per-client breakdown with block rates, rare-domain surfacing, and DGA-suspect
  lookups (flagged red when they were *passed through*).
- **`snare explain <domain>`** — block status, source category, traffic label, and
  DGA score for any domain.
- **Scheduled auto-refresh** (`snare install-refresh --hours N [--apply]`) — systemd
  timer / launchd StartInterval / Windows hourly Scheduled Task that rebuilds the
  blockmap so lists stay current automatically.
- Dashboard upgraded: DGA-threat KPI + panel, hourly activity, per-client block rates,
  rare-domain panel.
- 29 tests.

## [0.4.0] — 2026-07-04

### Added
- **Per-client profiles** (`--profiles FILE`) — NextDNS-style per-device policy:
  `{client_ip:{block_labels:[...],allow:[...]}}` (e.g. a kids device blocks the
  `social`/`advertising` label); `"*"` wildcard applies to all clients.
- **Client setup helper** (`snare setup <target>`) — copy-paste DNS-pointing
  instructions for windows / macos / linux / router / pihole, and a uBlock import path.
- 19 tests.

## [0.3.0] — 2026-07-04

### Added
- **DNS-over-HTTPS upstream** (`--doh cloudflare|google|quad9|adguard|<URL>`) — encrypted upstream resolution.
- **Allowlist** (`--allowlist FILE`) — never-block overrides, parent-domain aware.
- **Web dashboard** (`snare ui`) — NextDNS-style, Cognis-branded, self-contained, auto-refresh; `/api` JSON endpoint.
- **Run-as-service installers** (`snare install-service`, `--apply`) — systemd / launchd / Windows Scheduled Task, OS auto-detected.
- **Catalog expanded 24 -> 63 blocklists** (hagezi, OISD, 1Hosts, StevenBlack, uBlock, AdGuard CNAME/URL, frogeye, ShadowWhisperer, Phishing.Database, WindowsSpyBlocker, Perflyst, and more).
- 16 tests.

## [0.2.0] — 2026-07-04

### Added
- **Filtering DNS resolver** (`resolver.py` + `dnswire.py`) — an AdGuard/NextDNS-style
  server that listens for DNS queries, sinkholes blocked domains (0.0.0.0 / NODATA),
  forwards the rest upstream, with parent-domain matching. Pure stdlib UDP server.
- **Traffic study & labeling** (`labels.py`, `qlog.py`) — every query is categorized
  (advertising / tracking-analytics / telemetry / social / cdn-infra / malware-scam)
  and logged; `snare report` gives block-rate, category breakdown, top blocked/allowed,
  and top clients. NextDNS-style analytics, fully local.
- `snare map` (compile domain->category blockmap), `snare resolve`, `snare log`,
  `snare report`.
- Live-verified: real DNS query for a blocked subdomain sinkholed to 0.0.0.0.

## [0.1.0] — 2026-07-03

Initial public release.

### Added
- **24-list source catalog** across ads, trackers, AdGuard family, malware,
  phishing/scam, and redirect/malvertising (all keyless) — `catalog.py`.
- **Multi-format parser** (hosts / AdBlock-syntax / plain domains → normalized
  domains) — `parse.py`.
- **Merge + dedupe + compile** to hosts / domains / AdGuard-uBlock / dnsmasq —
  `compile.py`.
- HTTP client with on-disk cache + offline mode — `client.py`.
- CLI (`snare`): `sources`, `stats`, `build` (by `--categories` / `--sources`,
  any `--format`, `--offline`).
- Aggregation NOTICE documenting upstream sources and their licenses.
- Test suite (parsers, merge, compile formats, catalog integrity); CI across
  Python 3.9–3.13.
