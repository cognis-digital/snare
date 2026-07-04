# Changelog

Adheres to [Semantic Versioning](https://semver.org/).

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
