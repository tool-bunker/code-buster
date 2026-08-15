# Security assurance case

## Scope

Code Buster is an offline CLI that reads a repository, invokes Git with fixed argument vectors, stores a local content-addressed cache, optionally writes reports/baselines, and applies a small set of explicitly requested safe fixes. It does not send source code over the network or execute analyzed project code.

## Trust boundaries

| Boundary | Trust | Primary controls |
|---|---|---|
| Repository files → parser/rules | Untrusted | bounded file discovery, generated/binary filtering, no project-code execution, deterministic parsers |
| CLI arguments → filesystem/Git | Untrusted | option parsing, rejection of option-like Git refs, argument-vector subprocesses without a shell |
| Configuration → regex/globs | Semi-trusted | schema/type validation, known-key validation, constrained rule contracts |
| Cache/baseline → analysis | Semi-trusted | content/config/version cache keys, corrupt-cache rejection, stable fingerprints |
| Findings → file writes | Untrusted metadata | writes use configured local destinations; safe fixes only support known transformations |
| Build → installed artifact | Trusted release boundary | Dart package lock, CI on three operating systems, parity and benchmark release gates |

## Threats and controls

### Command injection

Code Buster invokes Git through direct process argument arrays and never interpolates repository text into a shell command. Changed-base values beginning with `-` are rejected before Git invocation. Tests cover option-like refs.

### Hostile source text

Analysis never imports, compiles, evaluates, or executes project code. Language adapters operate on text or Dart ASTs. Generated, minified, vendored, and auxiliary sources are classified before normal production analysis. Rule implementations must avoid super-linear unbounded matching; repository-local benchmarks and focused pathological fixtures detect major regressions.

### Path traversal and symlinks

Discovery does not follow directory symlinks. Analysis reads only paths returned by discovery. Fixes are restricted to discovered project-relative files and known transformations. Before expanding write-capable commands, Code Buster must canonicalize both root and destination immediately before writing and reject destinations outside the root unless the command explicitly documents an external output path.

### Regex denial of service

Built-in regexes are fixed by the application. User pattern rules are trusted repository policy, but malformed expressions are rejected. Real-repository performance ceilings and adversarial regex tests guard known expensive detector patterns. A future rule timeout should isolate user-provided regex execution.

### Cache poisoning

Cache keys include source hashes, effective configuration, command kind, tool cache version, and formatter configuration. Corrupt entries are ignored. Cache content is treated as local optimization, not executable data.

### Baseline suppression abuse

Baselines match stable finding fingerprints; they do not alter source discovery or rule execution. Reviews should treat baseline changes as security-sensitive policy changes. Planned triage metadata will add reason, owner, expiry, and rule version.

### Unsafe fixes

Fixes are opt-in, support dry-run previews, preserve multiline literal contents and line-ending state, and are limited to transformations with regression tests. Code Buster does not automatically apply arbitrary suggested patches.

### Secrets and telemetry

Code Buster has no LLM provider, telemetry exporter, or source upload path. It does not require API credentials. Reports may contain snippets and paths, so users must treat exported reports according to repository confidentiality.

## Fail-safe behavior

- Unknown commands, languages, formats, and invalid configuration fail explicitly.
- Empty discovery fails unless `--allow-empty` is supplied.
- Generated and auxiliary code do not enter production quality by default.
- Corrupt caches are ignored rather than trusted.
- Analysis errors must not be represented as successful coverage; the aggregated coverage ledger is the foundation for a versioned run manifest.
- Warning findings do not fail the quality gate unless repository policy raises their severity.

## Automated verification

| Control | Verification |
|---|---|
| Static correctness | `dart analyze` |
| Regression suite | `dart test` |
| Public API docs | `dart doc --dry-run` |
| Contract stability | Default-policy, CLI-contract, and report-schema tests |
| Precision/performance | `tool/precision_benchmark.py` and repository-local performance tests |
| Package contents | clean-tree `dart pub publish --dry-run` |
| Cross-platform compilation | GitHub Actions Linux, macOS, Windows matrix |
| Self-hosting | Code Buster production self-analysis with reviewed complexity findings and zero processing diagnostics |

## Open hardening work

1. Add canonical-path revalidation immediately before every baseline, report, and fix write.
2. Add bounded execution for project-provided regex rules.
3. Emit a signed/versioned run manifest with complete, partial, failed, and skipped states.
4. Add dependency vulnerability scanning for Dart packages to CI.
5. Archive checksums and parity/benchmark evidence with tagged artifacts.

## Security reporting

Do not disclose suspected vulnerabilities in public issues before maintainers have had an opportunity to assess them. Use the repository's private security-advisory channel when available and include the affected command, platform, minimal reproduction, and impact.
