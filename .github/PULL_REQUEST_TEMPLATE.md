<!-- Thanks for your contribution! Please fill in the sections below. -->

## Summary

<!-- One paragraph describing what this PR changes and why. -->

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New rule (Rego policy)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that changes existing behaviour)
- [ ] Documentation update
- [ ] Refactor / chore

## Checklist

- [ ] `make build` passes locally
- [ ] `./osc-policy rules test` passes (Rego unit tests + compliance validation)
- [ ] If a new rule is added : `noncompliant_example` and `compliant_example`
      are present in the metadata
- [ ] If a new rule is added : compliance mappings (`anssi_bp_028`,
      `secnumcloud_3_2`, etc.) are filled in
- [ ] If a new rule is added : at least one `*_test.rego` file accompanies
      the rule with a passing and a failing case
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] No real credentials in code or tests (use placeholders like
      `AKIAEXAMPLE0000000000`, `replace-me-fixture-string`)

## Additional context

<!-- Issue references (Fixes #123), screenshots, related PRs, etc. -->
