---
name: code-buster-rule-development
description: Add or change Code Buster rules with explicit evidence contracts, canonical catalog metadata, automatic pack discovery, conservative source handling, focused regressions, and native self-analysis.
---

# Code Buster rule development

Use this skill when changing detection, severity, taxonomy, confidence,
deduplication, source-role handling, safe-pattern handling, or reported
evidence. Run commands from the `code-buster/` repository root.

## Define the observable contract

Before editing, write down:

- the exact risky construct and why it matters;
- affected languages, versions, and frameworks;
- whether the result is actionable or advisory;
- the minimum semantic evidence and expected confidence;
- known safe and intentional forms;
- applicable production, test, generated, example, benchmark, and vendored roles;
- deduplication scope: occurrence, function, file, package, component, or repository;
- limitations that remain after implementation.

A token match is not automatically a defect. Prefer evidence from API
boundaries, ownership, sinks, control flow, configuration, parsed structure, or
framework conventions.

## Research before editing

1. Locate the owning analyzer, canonical JSON definition, execution pack, and focused tests.
2. Use language-server references before changing exported symbols.
3. Reuse `SourceAnalysisContext`, lexical masks, source indexes, cached regular expressions, graph facts, and path classifiers.
4. Check whether the language already parses once and exposes a shared representation.
5. Check how effective policy maps groups, taxonomy, advisory modes, baselines, and source roles.
6. Run the current detector against the motivating source and inspect representative findings.

Fix the general semantic cause. Never add repository-name, repository-path,
filename, or one-off source-text exceptions.

## Choose the strongest available analysis

Prefer, in order:

1. resolved language or framework semantics already exposed by an analyzer;
2. parsed structure and ownership;
3. token streams with established masking;
4. conservative lexical evidence.

Do not replace available structured evidence with regular expressions. Define
fixed regular expressions in `LazyLock`, and avoid rescanning the same source
for every rule when a shared index can compute the evidence once.

## Handle source text deliberately

Every rule must decide how it treats:

- comments and documentation;
- quoted, raw, multiline, and interpolated strings;
- nested or multiline syntax;
- generated files and framework wrappers;
- tests and embedded test modules;
- examples, fixtures, and benchmarks;
- vendored code;
- user configuration, baselines, and suppressions.

If a rule examines string contents, preserve strings while masking comments.
Never switch to raw-line matching merely to expose literals.

## Design for precision

- Require a real API call rather than a word occurrence.
- Require a sink, ownership boundary, or security context where an API also has safe uses.
- Honor project configuration before enforcing style.
- Distinguish parameterized SQL APIs from raw query construction.
- Distinguish public documentation from implementation narration.
- Coalesce repeated evidence when additional occurrences do not add a decision.
- Prefer abstaining over a medium-confidence result whose concept cannot be identified reliably.

Before adding an exclusion, state the general semantic category it represents.
If the explanation names only one repository symbol, the exclusion is too narrow.

## Catalog and execution contracts

Add one canonical definition at
`rules/catalog/<language>/<rule-id>.json`. The filename must equal `id`, and the
definition must declare severity, taxonomy, semantic maturity, requirements,
packs, implementation source, applicable languages or frameworks, and concrete
limitations.

Increment `version` when observable behavior changes in a way that must
invalidate caches or baselines.

`build.rs` validates and sorts catalog files and execution packs. Do not edit a
generated registry. For a new family, add one
`src/rule_packs/NNN-kebab-case.rs` file and point each owning rule's `packs`
field at that family. Adding a normal rule must not require parallel edits in
the catalog loader, engine, execution planner, and CLI.

## Regression requirements

Add permanent tests that defend behavior rather than implementation details:

1. A positive case that fails if the detector disappears.
2. At least two plausible negative cases.
3. A multiline or nested case when syntax permits it.
4. Comment and string examples for lexical detection.
5. Source-role behavior when classification matters.
6. Configuration behavior when policy matters.
7. Deduplication behavior when multiple occurrences are possible.
8. The motivating false positive reduced to a stable fixture.

Assert finding ID, path, line, confidence, related files, and count where those
are contractual. Do not assert private helper wiring or source text.

## Verify in escalating order

Run the narrowest affected Rust test first:

```sh
cargo test path_or_test_filter
```

Then run the complete repository checks:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo package --allow-dirty --locked
cargo build --release --locked
```

Run the changed native path and fresh self-analysis:

```sh
./target/release/cb version
./target/release/cb summary --advisory --no-cache --format json
```

Inspect every relevant remaining finding. A lower count is not proof of
precision, and zero self-findings is not proof that positive detection still
works. If a real repository motivated the change, rerun the same binary, root,
configuration, and command against that repository.

## Finish the change

- Remove obsolete helpers, aliases, suppressions, and comments.
- Update `CHANGELOG.md` for user-visible behavior.
- Keep catalog limitations and focused regression coverage synchronized.
- Confirm no cache, build output, external corpus, or throwaway fixture is tracked.
- Record verification commands and exact outcomes.
