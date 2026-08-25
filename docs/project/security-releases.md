# Security and releases

Interpret security findings and understand release assurance controls.

## Trust boundaries

Code Buster analyzes untrusted repository contents. Discovery does not follow directory symlinks, output paths are constrained, and reports distinguish processing failures from clean analysis. Treat source text, manifests, imported SARIF, and repository configuration as untrusted input.

## Finding semantics

A security heuristic can identify a confirmed defect, a suspicious pattern, or a review hotspot depending on rule metadata. Preserve that classification in CI and integrations. Do not present every hotspot as a vulnerability, and do not suppress diagnostics that make a run incomplete.

## Safe operation

- Review configuration and included source categories before enforcing a gate.
- Keep generated, vendored, test, and unsupported coverage visible.
- Preview `cb fix` changes before applying them.
- Pin the executable and report schema in automation.
- Report suspected vulnerabilities privately using the process in `SECURITY_ASSURANCE.md`.

## Release checks

A release verifies:

```sh
dart run tool/release_version.dart <tag>
dart format --output=none --set-exit-if-changed bin example lib tool/*.dart
dart analyze
dart run tool/default_contract.dart
dart test
dart doc --dry-run
dart pub publish --dry-run
python3 tool/release_evidence.py
```

The release workflow also compiles and tests platform artifacts. `release_version.dart` keeps the tag and `pubspec.yaml` aligned. GitHub generates the release notes automatically, and `release_evidence.py` validates archived precision evidence offline.

## Precision evidence

`tool/precision_benchmark.py` compares actual findings with reviewed accepted and rejected labels. A passing benchmark requires no unexpected finding, no missed accepted finding, and no rejected-case hit. Keep the report with its source revision and tool version.

See the repository's `SECURITY_ASSURANCE.md`, `RELEASE_READINESS.md`, `DEFAULT_COMPATIBILITY_POLICY.md`, and `PRECISION_BENCHMARK.md` for the maintained assurance records.
