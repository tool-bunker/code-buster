---
name: code-buster-rule-development
description: Add or change Code Buster rules with explicit evidence contracts, correct metadata and cache invalidation, conservative source handling, focused regressions, and native self-analysis.
---

# Code Buster rule development

Use this skill when adding a rule or changing detection, severity, taxonomy, confidence, deduplication, source-role handling, safe-pattern handling, or reported evidence.

Run all commands from the `code-buster/` directory.

## Define the observable contract

Before editing, write down:

- the exact risky construct and why it matters;
- affected languages, language versions, and frameworks;
- whether the result is actionable or advisory;
- for security results, whether evidence proves a vulnerability or only a hotspot;
- the minimum semantic evidence and expected confidence;
- known safe and intentional forms;
- applicable production, test, generated, example, benchmark, and vendored source roles;
- deduplication scope: occurrence, function, file, package, component, or repository;
- limitations that remain after implementation.

A token match is not automatically a defect. Prefer evidence from API boundaries, ownership, sinks, control flow, configuration, AST structure, or framework conventions.

## Research before editing

1. Locate the owning language registry, rule implementation, metadata, and focused tests.
2. Use language-server references before changing exported symbols.
3. Reuse existing lexical masks, cached regular expressions, AST representations, graph facts, and source classifiers.
4. Check whether the language plugin parses once and exposes a shared representation. Do not add a second parser or masking convention.
5. Check how `RulePolicy` maps groups, taxonomy, advisory modes, security hotspots, and source roles.
6. Run the exact current detector against the motivating source and record representative findings, not only a count.

Fix the general semantic cause. Never add repository-name, repository-path, filename, or one-off source-text exceptions.

## Choose the strongest available analysis

Prefer, in order:

1. resolved language or framework semantics already exposed by a plugin;
2. AST structure and ownership;
3. token streams with established masking;
4. conservative lexical evidence.

Do not replace available structured evidence with regular expressions. For lexical rules, use `cachedRegExp` rather than repeatedly constructing `RegExp` objects. Use mandatory capture accessors when the pattern contract guarantees a group.

## Handle source text deliberately

Every rule must decide how it treats:

- comments and documentation;
- quoted, raw, multiline, and interpolated strings;
- nested or multiline syntax;
- generated files and framework wrappers;
- tests and embedded test modules;
- examples, fixtures, and benchmarks;
- vendored code;
- user configuration, baselines, and suppression controls.

If a rule examines string contents, preserve strings while masking comments. Never switch to raw-line matching merely to expose literals.

## Design for precision

- Require a real API call rather than a word occurrence.
- Require a sink, ownership boundary, or security context where an API also has safe uses.
- Honor project configuration before enforcing style.
- Distinguish parameterized SQL APIs from raw query construction.
- Distinguish public documentation from implementation narration.
- Treat visitor hooks, analyzer orchestration, projections, adapters, and reporting boundaries according to their architectural role rather than their superficial member-access counts.
- Coalesce repeated evidence when additional occurrences do not add a new decision.
- Prefer abstaining over a medium-confidence result whose concept cannot be identified reliably.

Before adding an exclusion, state the general semantic category it represents. If the explanation names only one repository symbol, the exclusion is too narrow.

## Metadata and cache contract

When observable behavior changes, increment `RuleMetadata.version`, even when the rule ID and severity remain unchanged. This invalidates cached findings.

Metadata must accurately declare:

- default severity and group;
- taxonomy and semantic maturity;
- analysis requirements;
- languages, language versions, and frameworks;
- security kind;
- concrete limitations.

Use `SecurityFindingKind.hotspot` for a capability or trust boundary needing review when exploitation is not proven.

After metadata changes, update and inspect the generated contract:

```sh
dart run tool/default_contract.dart
dart run tool/default_contract.dart --update
```

The first command exposes drift; run the update only when the metadata change is intentional.

## Regression requirements

Add tests that defend observable behavior rather than implementation details:

1. A positive case that fails if the detector disappears.
2. At least two plausible negative cases.
3. A multiline or nested case when syntax permits it.
4. Comment and string examples for lexical detection.
5. Source-role behavior when classification matters.
6. Configuration behavior when policy matters.
7. Deduplication behavior when multiple occurrences are possible.
8. The motivating false positive or real-world construct reduced to a stable fixture.

Assert finding code, path, line, confidence, related files, and count where those are contractual. Do not assert private helper wiring or source text.

## Verify in escalating order

Run focused tests first:

```sh
dart test path/to/focused_test.dart
```

Then run repository verification without competing Dart processes:

```sh
dart analyze --fatal-infos
dart test
dart compile exe bin/cb.dart -o build/cb
```

Clear the analysis cache before final native self-analysis so stale findings cannot hide a metadata or invalidation mistake:

```sh
rm -rf .code-buster-cache
build/cb summary --advisory --format json
```

Inspect every remaining finding. A lower count is not proof of precision, and zero self-findings is not proof that positive detection still works.

If a real repository motivated the change, rerun the same compiled binary, root, configuration, and command against that repository. Compare representative findings and remaining false positives, not only totals.

## Finish the change

- Remove obsolete helpers, aliases, suppressions, and comments.
- Update the changelog when user-visible behavior changes.
- Keep metadata limitations and `test/fixtures/default_policy_contract.json` synchronized.
- Confirm no generated cache directory or throwaway fixture is included.
- Record verification commands and exact outcomes.
