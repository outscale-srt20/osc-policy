# Changelog

All notable changes to `osc-policy` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.8] - 2026-05-05

### Fixed

- OpenSSF Scorecard — Token-Permissions : permissions `contents: write` et
  `id-token: write` déplacées au niveau job dans `release.yml` et `sbom.yml` ;
  suppression de `packages: write` inutilisé.
- OpenSSF Scorecard — Pinned-Dependencies : épinglage de
  `trufflesecurity/trufflehog` à son SHA (était `@main`).
- OpenSSF Scorecard — Signed-Releases : ajout du bloc `signs:` cosign dans
  `.goreleaser.yml` pour la signature keyless des releases.
- OpenSSF Scorecard — Vulnerabilities : upgrade `golang.org/x/crypto` v0.42→v0.50
  (GO-2025-4116, GO-2025-4134, GO-2025-4135) et `aws-sdk-go` v1.44→v1.55.
- Mise à jour Go 1.24 → 1.25 dans tous les workflows CI.

## [0.0.7] - 2026-05-05

### Fixed

- `.mise.toml` : corrige l'installation via `mise` — le backend `github:` ne
  supporte pas le mot-clé `latest` (HTTP 404) ; utiliser une version explicite.

## [Unreleased]

### Added

- 70 Rego rules covering Outscale IaaS + OKS resources (Security, FinOps,
  Compliance categories).
- Multi-framework compliance mapping : ANSSI-BP-028, SecNumCloud 3.2,
  CIS Controls v8, ISO 27001:2022, ISO 27017.
- OKS collector via REST API (`api.<region>.oks.outscale.com`) for live
  scans on Outscale Kubernetes Service projects and clusters.
- OOS collector via S3-compatible API (`oos.<region>.outscale.com`) using
  `aws-sdk-go-v2`.
- `osc-policy explain <rule-id>` — display detailed documentation for a rule.
- `osc-policy init` — interactive wizard generating `.osc-policy.yaml`.
- `osc-policy fix --rule <id> --resource <id>` — print remediation snippets
  (always dry-run, never applies changes).
- `osc-policy suppress` — append entries to `.osc-policy-ignore` with reason
  and optional expiration date. Suppressions are filtered out of scan reports.
- `osc-policy diff <prev.json> <curr.json> [--fail-on-new]` — compare two
  scans, identify new/resolved findings; useful in CI to block regressions.
- `osc-policy report --framework <X> [--scan scan.json]` — generate a
  compliance report (markdown) targeting one framework, with per-control
  pass/fail status when a scan is provided.
- "Immediate action" section at the top of scan reports : top-3 critical
  findings with copy-pastable `explain` and `fix` commands.
- GitHub Actions workflows : CI, CodeQL, OSV-Scanner, SBOM, OpenSSF Scorecard,
  TruffleHog, GoReleaser release.
- Distribution via mise (backends `ubi` for releases, `go` for source).
- Integration snippets in `integrations/` : GitLab CI, MR commenter, Slack
  webhook, weekly cron live scan.

### Changed

- Renamed Go module path to `github.com/outscale-srt20/osc-policy`.
