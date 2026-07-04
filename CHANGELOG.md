# Changelog

Adheres to [Semantic Versioning](https://semver.org/).

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
