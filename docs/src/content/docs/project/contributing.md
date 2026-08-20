---
title: Contributing
description: Develop Code Buster, add rules, and build maintainable source fixtures.
---

Run development commands from the `code-buster/` directory. Read the repository's `CONTRIBUTING.md` for the complete contribution contract.

## Development checks

```sh
dart pub get
dart analyze
dart run tool/default_contract.dart
dart test
dart doc --dry-run
dart compile exe bin/cb.dart -o build/cb
./build/cb version
python3 tool/precision_benchmark.py
```

## Add a language rule

1. Add `lib/src/rules/<language>/<rule_name>.dart`.
2. Extend the appropriate self-contained, source-pattern, or semantic rule base.
3. Keep canonical metadata beside executable behavior.
4. Register it once in `lib/src/rules/<language>/rules.dart`.
5. Add a mirrored test under `test/rules/<language>/`.

Cover a real positive, a nearby negative, a plausible false positive, stable location data, and comments or strings when textual matching could encounter them.

## Inline samples or fixture files?

Keep a one-to-five-line lexical sample inline when the test varies one token or expression. Add a fixture when source is longer, substantially escaped, formatting-sensitive, line-sensitive, multi-file, or representative of a complete declaration.

Store source under:

```text
test/fixtures/languages/<language>/<scenario>/
```

Load it with `sourceFixture` from `test/support/source_fixture.dart`. Map keys represent repository-visible paths; fixture storage paths do not need to match them. Never name a Dart source fixture `*_test.dart`, because the Dart runner will discover it as a test.

Do not format intentionally malformed or oddly formatted fixtures. Explain suspicious fixture syntax when its purpose would otherwise be mistaken for an accidental error.

## Public API

External integrations import `package:code_buster/code_buster.dart`. Files under `lib/src/` are private implementation and test surfaces.

## Benchmarks and contracts

Run `tool/update_inventories.py` after changing the command enum. Run `dart run tool/benchmark.dart test/fixtures/mixed_realistic 5` for performance-sensitive changes. Update compatibility snapshots only after reviewing the behavior change they expose.
