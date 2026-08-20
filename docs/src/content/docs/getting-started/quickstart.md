---
title: Quickstart
description: Analyze a repository, understand coverage, and investigate a finding.
---

Run Code Buster from the repository you want to analyze. Configuration is optional.

## Analyze production source

```sh
cb summary
```

The default analysis detects supported languages and frameworks, selects production source, and classifies conventional tests, examples, fixtures, benchmarks, generated code, and vendored files separately.

For a machine-readable report:

```sh
cb summary --format json
```

## Include auxiliary source

```sh
cb summary --include-tests
cb summary --include-examples
cb summary --include-vendored
cb summary --all
```

The summary coverage ledger distinguishes selected, test, example, vendored, generated, unsupported, binary, ignored, and unchanged files. Inclusion changes selection; it does not erase classification.

## Explain selection and findings

```sh
cb inspect path/to/file.dart
cb explain <rule-id>
cb why path/to/file.dart
cb related path/to/file.dart
```

Use `inspect` to understand file classification. Use `explain` for rule rationale and remediation. Use `why`, `related`, and `path` when investigating repository wiring.

## Review quality

```sh
cb score
cb quality
cb hotspots
cb plan
cb actions
cb review
```

These views organize the same analysis evidence for different decisions: prioritization, quality gates, high-risk areas, remediation, and code review.

## Add configuration only when needed

```sh
cb init
cb config explain
```

`cb init` creates a minimal `code-buster.toml`. `cb config explain` displays effective defaults, inferred repository policy, file configuration, environment input, and CLI overrides.
