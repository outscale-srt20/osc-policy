# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in `osc-policy`, please report it
**privately** rather than opening a public issue.

- **Preferred channel** : GitHub Security Advisories
  ([Report a vulnerability](https://github.com/outscale-srt20/osc-policy/security/advisories/new))
- **Alternative** : email the maintainer directly via the contact listed on
  the repository's owner profile.

Please include in your report :

- A clear description of the vulnerability and its impact.
- Steps to reproduce (proof of concept welcomed).
- Any suggested mitigation, if known.
- Your name / handle for credit (or "anonymous" if preferred).

## Response timeline

| Step | Target delay |
| --- | --- |
| Acknowledgement of the report | 5 working days |
| Initial triage and severity assessment | 10 working days |
| Fix released (depending on severity) | 30 to 90 days |
| Public disclosure (CVE if applicable) | After fix release |

## Scope

In scope :

- Bugs in the `osc-policy` binary itself (CLI, scan engine, collectors).
- False positives / negatives in security-critical Rego rules that could
  mislead users into believing their infrastructure is compliant.
- Supply chain issues in our build/release pipeline (GoReleaser, GitHub
  Actions workflows).

Out of scope :

- Vulnerabilities in the Outscale platform itself — please report those to
  [Outscale's security team](https://outscale.com/contact/) directly.
- Vulnerabilities in third-party dependencies — those should be reported
  upstream. We track dependency vulnerabilities via OSV-Scanner / Dependabot.

## Supply chain

We provide :

- **Signed releases** via GoReleaser.
- **SBOM (Software Bill of Materials)** attached to each release (Syft).
- **Reproducible builds** with pinned dependencies.
- **Continuous scanning** via OpenSSF Scorecard, CodeQL, OSV-Scanner and
  TruffleHog (see `.github/workflows/`).

## Verification

To verify a release binary :

```bash
# Download release + checksums
curl -sSfL https://github.com/outscale-srt20/osc-policy/releases/download/vX.Y.Z/checksums.txt \
  | sha256sum -c
```
