# Contributing to Code Buster
Thank you for improving Code Buster. Contribution should preserve the core.

## Before you start
- For a bug, include a minimal repository or source fixture that reproduces it.
- For a new rule, explain the unsafe or costly behavior it detects and the cases
  that must not be reported.
- Report suspected vulnerabilities privately as described in
  [SECURITY_ASSURANCE.md](SECURITY_ASSURANCE.md#security-reporting). Do not
  open a public issue before maintainers have assessed the report.

## Development setup

Code Buster requires Dart 3.11 or newer. Run commands from the `code-buster/`
directory:

```sh
dart pub get
dart run bin/cb.dart version
```

Build the native executable with:

```sh
mkdir -p build
dart compile exe bin/cb.dart -o build/cb
./build/cb version
```

The workspace installer builds the current checkout and installs `cb` under
`~/.local/bin` by default:

```sh
../install-code-buster.sh
```

## Making changes

Keep changes focused and follow existing module boundaries:

- CLI commands live under `lib/src/cli/`.
- Language adapters live under `lib/src/languages/<language>/`.
- Language rules live under `lib/src/rules/<language>/`.
- Repository-wide rules live under `lib/src/rules/`.
- Tests mirror the relevant implementation area under `test/`.
- Public integrations must import `package:code_buster/code_buster.dart`, not
  private files under `lib/src/`.

Do not manually edit generated rule catalogs. `RuleCatalog` derives metadata
from executable rules and language manifests. When rule behavior changes,
increment that rule's metadata version so persistent analysis caches are
invalidated.

If the CLI command enum changes, refresh the live command inventory:

```sh
tool/update_inventories.py
```

## Adding or changing a rule

A rule contribution must establish useful precision, not merely match a source
pattern.

For a language rule:

1. Add `lib/src/rules/<language>/<rule_name>.dart`.
2. Extend `SelfContainedRule`, `SourcePatternRule`, or `SemanticRule<T>`.
3. Keep canonical `RuleMetadata` beside the implementation.
4. Register the rule once in `lib/src/rules/<language>/rules.dart`.
5. Add a mirrored test under `test/rules/<language>/`.

Repository-wide rules are registered in
`lib/src/rules/repository_rules.dart`. Use `RuleContext.report` so findings take
their identifier, severity, explanation, and remediation from canonical
metadata.

Every rule test should cover:

- a real positive case;
- a nearby negative case;
- at least one plausible false-positive case;
- stable finding location and message data when these are part of the contract;
- comments and string literals when a textual matcher could encounter them.

Prefer parsed or semantic analysis when text matching cannot distinguish those
cases reliably. `SourcePatternRule` already ignores comments and quoted strings
by default.

`JavaResourceNotClosedRule` and its test are the representative built-in rule
example.

## Writing tests and source fixtures

Keep the assertion and the smallest input that explains it close together. A
one- to five-line lexical example may remain inline when the test varies a
single token or expression. Use a source fixture when the sample is longer,
contains substantial escaping, represents a complete declaration, or depends
on formatting, comments, imports, line numbers, or multiple files.

Store language samples under
`test/fixtures/languages/<language>/<test_scenario>/`. Use the scenario name
from the test and preserve normal source extensions, for example:

```text
test/fixtures/languages/cpp/cpp_adapter_test/
  main.cpp
  widget.hpp
```

Load these files with `sourceFixture` from
`test/support/source_fixture.dart`. The map key passed to an adapter or rule
must be the repository-relative path the analyzer should observe; it does not
have to match the fixture's path on disk:

```dart
final Map<String, String> sources = <String, String>{
  'src/main.cpp': sourceFixture('cpp/cpp_adapter_test/main.cpp'),
  'src/widget.hpp': sourceFixture(
    'cpp/cpp_adapter_test/widget.hpp',
  ),
};
```

Fixture files are read exactly as stored. Do not run a language formatter over
fixtures that intentionally exercise malformed syntax, unusual indentation,
line endings, trailing whitespace, or parser recovery. Put such cases in a
clearly named scenario and add a short comment in the fixture when its purpose
would otherwise be mistaken for an error. Dart fixture filenames must not end
in `_test.dart`, because `dart test` discovers that suffix as an executable test.

Prefer one scenario directory per behavior. Reuse a fixture only when multiple
assertions intentionally describe the same source contract; unrelated tests
should not share a large catch-all sample. For dependency resolution, module
wiring, classification, or repository discovery behavior, use a multi-file
fixture rather than an inline map so the test exercises realistic paths.

Run the narrowest affected test while developing:

```sh
dart test test/languages/<language>_adapter_test.dart
dart test test/rules/<language>/<rule_name>_test.dart
```

Before submitting, run the complete verification commands below. A fixture
migration is incomplete if the focused test passes but `dart test` discovers a
fixture as a test file or another suite depends on the old inline sample.

## Formatting and verification

Format production Dart sources exactly as CI does:

```sh
dart format bin example lib tool/*.dart
```

Run the focused test for the changed behavior first, then the complete checks:

```sh
dart analyze
dart run tool/default_contract.dart
dart test
dart doc --dry-run
dart compile exe bin/cb.dart -o build/cb
./build/cb version
python3 tool/precision_benchmark.py
```

For performance-sensitive analysis changes, also run the repeatable mixed
language benchmark:

```sh
dart run tool/benchmark.dart test/fixtures/mixed_realistic 5
```

Code Buster supports Dart 3.11 as its minimum SDK. Avoid language or dependency
changes that break the `3.11.0` CI job unless the minimum-version change is an
explicit project decision.

## Pull requests

A pull request should:

- state the user-visible problem and the chosen solution;
- list the commands used to verify it;
- include regression coverage for changed behavior;
- call out rule-count, schema, cache, CLI, or public-API changes;
- avoid unrelated formatting or generated-file churn;
- preserve machine-readable output compatibility unless the change explicitly
  updates the corresponding schema contract.

Keep commits reviewable. A maintainer may request narrower matching or more
negative fixtures when a rule's precision is not demonstrated.

By contributing, you agree that your contribution is provided under the
project's [MIT License](LICENSE).