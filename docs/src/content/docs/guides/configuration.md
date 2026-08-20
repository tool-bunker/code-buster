---
title: Configuration
description: Control language selection, source classification, rules, quality gates, and architecture policy.
---

Code Buster reads an optional `code-buster.toml` from the analyzed repository. With no file, repository defaults infer languages, frameworks, source categories, and formatter policy.

## Precedence

Explicit CLI options override environment and file configuration. Explicit classification globs override inferred repository profiles. Inspect the result with:

```sh
cb config explain
cb inspect path/to/file
```

## Language and quality policy

```toml
languages = ["dart", "python", "typescript"]

[quality]
profile = "standard" # standard, strict, or security
gates = ["findings == 0", "debt_minutes_per_file <= 5"]

[analysis]
min_duplication_lines = 6
complexity_threshold = 10
cognitive_threshold = 15
max_file_lines = 500
max_function_lines = 80
```

Use `languages = ["auto"]` to detect substantial languages from source files and manifests.

## Source classification

```toml
[classification]
production = ["tools/release/**"]
test = ["verification/**"]
generated = ["src/schema_output/**"]
```

Production source is analyzed by default. Tests, examples, fixtures, benchmarks, vendored code, and generated code remain visible in coverage while excluded from normal findings unless requested.

## Rule selection

Configure rule groups, disabled rules, and per-rule severity only when repository policy differs from defaults. Rule IDs are stable contract identifiers; use `cb rules` and `cb explain <rule-id>` before adding overrides.

## Architecture boundaries

Architecture policy can restrict allowed source-to-target dependencies and define project entry points. Prefer project-relative globs and validate them with `cb graph`, `cb structure`, and `cb path <source> <target>`.

## CI behavior

Set CI failure behavior explicitly rather than relying on interactive defaults:

```toml
[ci]
fail_on_findings = true
```

Commit configuration with the repository so local and CI analyses use the same policy.
