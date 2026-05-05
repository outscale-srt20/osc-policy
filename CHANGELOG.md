# Changelog

All notable changes to `osc-policy` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
