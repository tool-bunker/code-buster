# Contributing to Code Buster

Contributions should keep rule behavior precise, deterministic, and easy to review.

## Development setup

Code Buster requires Rust 1.88 or newer.

```sh
cargo build --locked
cargo run -- version
```

## Project layout

- Language analyzers: `src/languages/<language>/`
- Repository-wide analyzers: `src/rules/`
- Auto-discovered execution packs: `src/rule_packs/`
- Canonical rule definitions: `rules/catalog/<language>/<rule-id>.json`
- CLI argument contract: `src/app/cli.rs` (`clap` declarations)
- CLI command implementations: `src/app/commands/`
- Integration tests: `tests/`

`build.rs` discovers every JSON file below `rules/catalog/` and every Rust file below `src/rule_packs/`. It validates and sorts both registries before generating build artifacts under `target/`; never edit those artifacts.

Declare new options once on `ParsedArguments`; do not add a parallel argument
scanner. A bare `cb` invocation is `summary`: it reports actionable findings
in detail and summarizes count-mode advisory findings unless `--advisory` or
`--all-findings` is supplied. The default text report keeps scope and stage
timings behind `--verbose`; machine-readable report contracts are unchanged.

Shared summary analysis uses the delayed progress renderer in
`src/reporting/progress.rs`. Progress is written to stderr only after 180 ms and
is cleared before the final report. It is disabled for redirected streams,
machine formats, `--ci`, `--output`, `CI`, `NO_COLOR`, and `TERM=dumb`.
Human-readable reports use ANSI color only when stdout is interactive.

`dead-export` and `re-export` are command-scoped rules: `cb dead` invokes `src/graph/export_analysis.rs`. They must not run in the default summary pack because explicit dead-code analysis can be substantially noisier than the default review surface.

## Adding a rule to an existing family

1. Add the detector to the matching analyzer, or keep a focused detector beside that analyzer and expose it from the family module.
2. Add `rules/catalog/<language>/<rule-id>.json`. The filename must equal `id`, its parent directory must equal `language`, `packs` must name the execution family that calls the detector, and `implementation` must point to the Rust source that declares the emitted rule ID.
3. Add focused regression coverage for positive, negative, and plausible false-positive cases.
4. Run the focused test, then the complete checks below.

No edits are required in `src/rules/catalog.rs`, `src/engine/analysis_engine.rs`, `src/engine/execution_plan.rs`, the `rules` command, or a generated registry.

A canonical definition has this shape:

```json
{
  "id": "rust-example",
  "language": "rust",
  "group": "reliability",
  "listingTitle": "Review the example",
  "title": "Review the example",
  "mvvm": false,
  "defaultSeverity": "warn",
  "legacyGroup": "core",
  "why": "The detected behavior can fail under the stated conditions.",
  "suggestion": "Use the safe alternative.",
  "version": 1,
  "semanticMaturity": "token",
  "securityKind": "none",
  "taxonomy": ["reliability"],
  "requirements": ["sourceText"],
  "packs": ["rust"],
  "implementation": "src/languages/rust/rules.rs",
  "languages": ["rust"],
  "frameworks": [],
  "languageVersions": [],
  "limitations": ["State the important precision boundary."]
}
```

`listingTitle` is the short title shown by `cb rules`. `title`, `why`, and `suggestion` are the explanatory contract used by findings and `cb rules RULE_ID`.

`build.rs` watches every `implementation` source and rejects definitions whose file is missing, points outside `src/`, points at a standalone test file, or does not contain the exact rule ID. Dynamically selected rules must therefore declare their complete IDs beside the detector rather than constructing undocumented IDs with `format!`. When implementations share a helper, pass the literal ID from each catalog-listed implementation source.

Increment `version` whenever behavior changes in a way that should invalidate persistent baselines or analysis caches.

## Adding an execution family

Add one `src/rule_packs/NNN-kebab-case.rs` file. `NNN` determines deterministic execution order; `kebab-case` must equal the pack's `id`. The file declares its family, applicable languages or framework, shared-index requirements, and analyzer callback:

```rust
use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "rust-example",
    "rust-example",
    &["rust"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(find_examples(
        context.source_context,
    )))
}
```

Point each owning rule definition's `packs` field at the pack's family. The build discovers the file automatically; do not add module declarations, engine branches, prefix routing, or registry entries. Keep a standalone detector in the pack file, or call a reusable analyzer module when several packs share it.

Use `RulePack::after_main` only when a pack consumes earlier findings. Set `needs_functions` or `needs_yagni_index` only when the callback uses those shared indexes.

## Adding a language

Add extensions and aliases to `src/languages/registry.rs`, then add auto-discovered packs for its analyzers. Language recognition remains the only central integration because discovery must map files to a language before any pack can run.

## Rule tests

Every new rule should cover:

- a real positive case;
- a nearby negative case;
- at least one plausible false positive;
- stable path, line, and message data where applicable;
- comments and string literals when textual matching could encounter them.

Prefer parsed or semantic evidence when text matching cannot distinguish safe and unsafe cases reliably.

### Rust panic-rule precision

`rust-unwrap` and `rust-expect` analyze production code. Discovery excludes conventional Rust test modules named `test.rs` or `tests.rs`; inline `#[test]` items and `#[cfg(test)]` modules are also excluded. A targeted `#[allow(clippy::unwrap_used)]` or `#[allow(clippy::expect_used)]` is the explicit escape hatch for a project-specific invariant.

The detector ignores only invariants it can establish from source structure: literal regexes, formatted regexes whose dynamic arguments all use `regex::escape`, regex capture group zero, generated catalog lookups, catalog severity parsing, and UTF-8 reconstruction whose message documents the byte-preserving invariant. Dynamic regexes, optional or unchecked capture groups, and runtime `Option` or `Result` values remain reportable.

### Rust repository-policy rules

Rust repositories with checked-in CI should run `cargo fmt --all -- --check`
or an equivalent direct `rustfmt --check`, and Clippy alongside their normal
Cargo build or test command. Code Buster accepts toolchain-qualified commands such as
`cargo +stable clippy`; it does not require the version-sensitive `pedantic`,
`nursery`, or beta lint sets.

Repositories with a committed `Cargo.lock` should audit resolved dependencies
in CI and pass `--locked` or `--frozen` to direct build, check, test, and Clippy
commands. Code Buster recognizes `cargo audit`, `cargo deny check`, the RustSec
audit action, and the cargo-deny action. Code Buster only checks for these gates;
it does not execute networked audit tools during analysis.

Binary packages should commit an applicable lockfile. Production packages
should declare `package.rust-version`, directly or through workspace
inheritance, and registry dependencies should use reviewed version ranges
rather than `*`. Test, fuzz, example, benchmark, generated, and vendored
manifests follow the shared path classification and are excluded. Manifests
that opt into unstable `cargo-features` are exempt from the stable MSRV check.

Workspace analysis resolves production members from `members` and `exclude`
patterns while treating nested `[workspace]` manifests independently. Virtual
workspaces should declare the resolver matching their newest member edition.
Cargo root-only profile, patch, and replace tables must stay at the owning
workspace root, as must the effective lockfile. Non-virtual multi-package
workspaces should make CI scope explicit with `--workspace`, complete
`default-members`, or per-package commands.

Code Buster groups dependency policy by crate instead of emitting one finding per
member: differing direct registry requirements in internal or private members
produce one drift finding, and the same requirement repeated in at least three
such members produces one advisory to use `workspace.dependencies`. Published
workspace packages are excluded because their dependency floors can diverge
intentionally.

Public functions in publishable library packages should expose typed errors.
`rust-public-anyhow-result` reports direct `anyhow` return types and locally
declared aliases, while allowing applications, binary-only packages, and
explicitly internal or unpublished libraries to use `anyhow`.

Keep credentials outside Rust source. `rust-hardcoded-secret` intentionally
limits itself to direct string literals assigned to credential-shaped `const`,
`static`, or `let` names and excludes placeholders and conventional non-secret
token identifiers.

Implement `From<Source> for Target` rather than `Into<Target> for Source` when
the conversion is owned by either type. Rust supplies the corresponding `Into`
implementation automatically.

`repeated-condition` ignores byte-scanner cursor mechanics. Repeated business-policy predicates remain findings and should usually become a named predicate.

## Verification

Run the narrowest affected test while developing. Before committing:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo package --allow-dirty --locked
cargo run --locked -- version
```

For performance-sensitive changes, run `cb summary --profile` on the affected
real repository and compare the slowest rule packs and shared analysis stages.
The profiler bypasses analysis caches automatically. Verify exact finding
parity unless behavior intentionally changed.

## Preparing a release

Add user-visible changes under `## Unreleased`, then prepare the Cargo package
version, lockfile, pinned integration install command, and changelog heading together:

```sh
./tool/prepare-release.sh 0.10.0
```

The script requires Python 3 and is idempotent for an already-prepared version.
It does not create a tag, push commits, or publish a release. Run the
verification commands above, commit the prepared sources, and dispatch the
release workflow from `main`. The workflow builds and smokes every native
artifact before publishing the crate through crates.io Trusted Publishing, then
publishes the GitHub release.
