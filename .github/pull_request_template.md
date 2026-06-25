# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Daniel Wu.

## Summary

<!-- 1-3 bullet points describing what this PR changes and why. -->

-

## Type of change

<!-- Check one or more. -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Refactor (no functional change)
- [ ] Docs / build / CI
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)

## Test plan

<!-- How did you verify this change? Check the boxes that apply. -->

- [ ] `make fmt` passes
- [ ] `make vet` passes
- [ ] `make test` passes (race + unit + integration)
- [ ] `make lint` passes (golangci-lint v2)
- [ ] `make fuzz FUZZTIME=30s` passes
- [ ] Manual verification (steps below)

<!-- For UI / protocol behavior, note manual test steps here. -->

## Checklist

- [ ] New files begin with the MIT SPDX header and copyright notice
- [ ] Added or updated tests for the change
- [ ] Updated relevant docs (`README.md`, `docs/`, `CONTRIBUTING.md`)
- [ ] Commit messages follow `type(scope): description`
- [ ] No secrets, keys or tokens in code, logs, or commit messages
- [ ] Security-sensitive changes (auth, crypto, TLS) called out explicitly

## Security impact

<!-- If this changes authentication, cryptography or TLS code, describe the
impact and any threat-model considerations. Write "None" if not applicable. -->
