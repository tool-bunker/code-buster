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
- GitHub Action: root `action.yml`, implementation and Node tests under `action/`

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

Report-producing commands share `src/reporting/report.rs::write_report`: `--output`
selects a file-only sink, preserves the renderer's bytes and final newline, and
leaves stdout empty. Relative report paths resolve from the invocation directory,
not `--root`; the parent directory must already exist. Save and flush the report
before deciding finding or quality-gate exit status, and propagate write errors
through the normal stderr/error exit path. This applies to summary/review (including
plan/actions), quality views, duplication, dead, graph, inspect views, rules, doctor,
and `config --files`. Baseline ledger paths, fix/init mutations, configuration
inspection/migration, completions, and updater output have separate contracts.

Human-only finding wording belongs in `src/reporting/finding_message.rs`, shared
by terminal and Markdown reports. Keep canonical finding messages unchanged
unless intentionally changing the machine contract: they participate in finding
identity and persistent controls. Recognize the emitter's message shape before
reformatting it; unfamiliar or imported messages must retain their original
information. Supporting evidence belongs behind `--verbose`, not in the headline.

`dead-export` and `re-export` are command-scoped rules: `cb dead` invokes `src/graph/export_analysis.rs`. They must not run in the default summary pack because explicit dead-code analysis can be substantially noisier than the default review surface.

## GitHub Action

The root metadata runs `action/index.mjs` on Node.js 24, without npm runtime
dependencies. The optional engine version defaults to this checkout's literal
Cargo package version; an explicit `executable` uses that native binary instead.
The Action shares Code Buster release tags and has no separate version series.

From the repository root:

```sh
npm --prefix action run check
npm --prefix action test
```

Native CI calls `uses: ./` with each just-built executable. Action download
smokes explicitly select an already published engine, so source verification
never needs the next release's artifacts before publication. See
[`action/README.md`](action/README.md) for behavior and permissions.

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

`oop-feature-envy` uses method declaration locations, including overloads. Do not
replace these with the class header or merge methods merely because their
rendered messages match.

Shared OOP parameter clumps need independent declarations, not explicit overrides
or Java constructors that only forward the same parameters to `super` or `this`.
Own-type access is not feature envy. Keep qualified type references and completed
builder construction out of navigation evidence without exempting arbitrary
fluent calls. Template-workflow comparisons use four to ten outer calls;
nested argument calls and control conditions are not independent workflow steps.
Keep nested call differences in the comparison so this counting boundary does
not make workflows with other differing behavior appear equivalent.

Java builder projection exclusions require a whole-method completed
`Type.builder()`/`newBuilder()` return and parameter-rooted, zero-argument bean
accessor calls in arguments. Do not exempt arbitrary DTOs or builder usage:
other argument calls, mutation, callbacks, unfinished builders, and extra
statements remain eligible, as do `getAnd...`/`getOr...` operations.
Constructor-only forwarding may append fixed boolean/null defaults, but derived
arguments and additional work still contribute independent clump evidence.

Java package/import directives do not supply duplicated runtime logic; retain
code sharing the same physical line and preserve real duplicate bodies.
Trivial annotated Java override getters are contract boilerplate rather than
duplicated behavior. Keep computed getters, extra work, unannotated methods and
code sharing an accessor line comparable. Excluded methods need source-unique
boundaries so filtering cannot fuse separate runtime fragments.
Broad-catch checks retain conditional recovery and exception translation, but
exclude direct rethrows of the original binding after logging-only observation.
Custom Java fluent factories count as construction only when a unique project
type declares a zero-argument factory returning a nongeneric `...Builder` type
and the chain completes at `build()`. Unknown or ambiguous receivers stay eligible.

Java Future checks distinguish discarded task handles from direct arguments passed
to another call and expression results returned through an immediate list-stream
`map`. Keep `forEach` consumers and discarded calls inside block-bodied mapping
lambdas eligible; do not borrow a local list's type for another object's member
or assume unknown fluent APIs preserve Future results.

Java loop-performance findings describe source patterns, not measured bottlenecks.
String accumulation includes simple identifier-prefix prepending, but intermediate
prefix reads can require materialization on each iteration. Membership indexes
must preserve ordering where used, collection updates, and equality/hash-code
stability; do not turn small or bounded list checks into mandatory Set refactors.

Prefer parsed or semantic evidence when text matching cannot distinguish safe and unsafe cases reliably.

Keep compiler fixtures out of default production scans: underscore-separated test-case
and test-fixture directories, exact `compile_fail`/`compile-fail` directories, Rust
`tests_*.rs` modules, and Rust `ui/` cases paired with `.stderr` expectations are test code.
Ordinary application UI, `compile_failure` directories, and production `compile_fail.rs`
modules stay production. Preserve `--include-tests`, `--all`, explicit classification
overrides, and `cb inspect`.

Conventional `testData` and `test_data` directories are test support. Sample-, mock-,
or fixture-named JavaScript/TypeScript modules exporting literal objects or arrays
can also be test support when real relative test imports establish their use and no
visible production import, re-export or literal file-read path references them.
This inference requires unrestricted automatic discovery: language/path filters,
custom ignores and changed-file scans cannot prove the absence of runtime consumers.
Names alone do not exclude files. Computed module loaders, unresolved escaped
specifiers, executable data initializers and production overrides remain conservative.
Keep coverage/exclusion lists separate from runtime consumption, and retain normal
calls named `require` in other languages. Share lexical/import helpers rather than
adding a second parser; preserve scope flags, cache inputs and inspection output.

Python string-accumulation inference must distinguish byte prefixes from text
initializers. C# broad-catch advice must respect closed-set positive exception
filters without assuming that helper predicates, negative filters or aliases
establish a specific recovery boundary.

Respect explicit existing lint decisions. TypeScript rules consume Deno file and
next-node directives plus explicit `lint.rules.include`/`exclude` settings in
`deno.json` or `deno.jsonc`; unhandled tags and dynamic configuration are not inferred.
Scope comments to real syntax, not lookalike directives inside strings.

### Spring reliability rules

The Java-only `spring` pack requires production Maven or Gradle metadata: real
Spring dependencies or a Spring Boot parent/plugin, not an annotation name alone.
Both `build.gradle` and `build.gradle.kts` are auxiliary cache inputs. The nearest
manifest owns a source file; unrelated nested modules do not inherit Spring just
because their directory has a Spring ancestor. Maven inheritance follows a local
parent only when its declared coordinates and resolved relative path match.
Comments, descriptive strings, test-only dependencies, and test/generated/vendor
manifests are not framework evidence. Dynamic Gradle configuration, version-catalog
aliases, unresolved Maven properties, profile activation, and remote parents are
not evaluated.

Detectors bind explicit/wildcard imports or fully qualified canonical annotations.
Managed-class evidence is limited to top-level, nonabstract classes with canonical
stereotypes or an unambiguous explicit `@Bean` return type. Class-level `@Async`
and `@Transactional` are included.
Canonical Boot `@AutoConfiguration` classes also establish managed configuration
and can register bean return types across packages within the same module.
`spring-async-return-type`, `spring-scheduled-parameters`, and
`spring-async-post-construct` are actionable reliability warnings. Async return
checks accept `void`, `Future`, `CompletableFuture`, and recognizable subtypes.
Rejections are limited to primitives, arrays, and bound known JDK/reactor types;
unknown user types and type parameters are not assumed invalid. Scheduled checks concern
parameters, not return types: reactive scheduled methods may return a value.

`spring-transactional-self-invocation` and `spring-async-self-invocation` default to
count-mode advisory findings. They group direct, resolved same-class calls by
target and explain bypassed requested proxy advice, not that all transactions
disappear. Explicit rule/group configuration and severity overrides still win.
Self-invocation abstains on classes with `extends`/`implements`, same-name
overloads, varargs or private/static targets, explicit generic receiver calls,
other receivers, lambdas, and anonymous/local/inner classes. Findings retain the
primary annotation location and grouped call locations in `code_flow`.
Matching caller transaction settings are excluded for `REQUIRED`, `SUPPORTS`,
`MANDATORY`, `NEVER`, and `NOT_SUPPORTED`; `REQUIRES_NEW` and `NESTED` still need
their own interception boundary.
Explicit per-module AspectJ mode suppresses
the corresponding proxy checks; async lifecycle warnings do not apply in that mode.
Source-role overrides, finding controls, and baselines remain shared engine policy.

### Reviewing advisory evidence

Classify source-backed samples as a confirmed detector error, a real construct
whose trade-off needs context, or unresolved evidence. A threshold crossing or
performance pattern is not proof of a defect or slowdown. Keep legitimate
positives when tightening a detector; check grouped related locations as well
as the primary finding. Capped duplicate groups can be replaced by other groups,
so an unchanged total does not mean the false evidence remains.

Rust complexity excludes recognized quoted syntax, not evaluated span expressions
or ordinary runtime macro bodies. `match` alternatives remain measured. A function
containing only one unguarded literal/constant lookup map can be excluded from
refactoring advice without changing its metrics. Single-arm macro forwarding is
recognized only when one captured token tree goes exclusively to a proven quote
macro, with no branching setup or runtime reuse. Explicit declared-sibling imports
and aliases require a matching provider export. Other forwarding, ambiguous modules,
path-mapped modules, and unresolved imports remain conservative, not certified.

Review CB's own advisory findings too. Prefer a useful simplification, but do not
scatter cohesive dispatch or parser state solely to lower a counter, increase
thresholds, or add blanket ignores. A retained advisory needs concrete branch-order,
state, or contract invariants and relevant behavioral coverage; “it is a parser”
is not enough. Record the reason when retaining contextual advice or an intentional
invariant panic.

Report rendering retains some contextual complexity: inspection keeps scope
classification and format-specific evidence together, while review plans keep
first-seen grouping, stable priority ordering, and bounded evidence in one flow.
The report-sink closure adds lexical nesting without another analysis pass or
an intermediate report buffer. Preserve flush-before-policy-exit behavior;
`tests/cli/output.rs` covers both formats, excluded inspections, plan ordering
parity, write errors, and reports saved on finding/quality-gate failure.

### JavaScript and TypeScript parser boundaries

Comment and string scanners must recognize regex literals before interpreting
their quote or comment-shaped contents. Reuse the shared regex boundary scanner;
do not infer regex boundaries with another pattern. Keep division, escaped slashes,
character classes, Unicode, malformed line endings and template expressions in
behavioral coverage. Mask literal examples without losing subsequent runtime
calls or moving their reported lines.

JSON syntax recovery may live in a caller rather than the parser helper. Recognize
only private synchronous named module-level helpers whose references are all direct
same-file calls inside simple completed `try/catch` boundaries without rethrow.
Keep exported, aliased, asynchronous, deferred and unresolved paths reportable.
Use executable tokens, not schema-related names, as evidence; a schema's
`safeParse` cannot catch an earlier `JSON.parse` exception. Caller recovery does not
validate result shape or disable local-storage and security advice.

### JavaScript and TypeScript loop waits

Treat bare `for (;;)` and `while (true)` alike as service-loop contexts for
sequential-await advice. Use the nearest enclosing loop: a finite nested loop
remains independently reviewable, and leaving an inner service loop must restore
the outer loop's policy. Initialized or updating `for` headers remain ordinary
review contexts. Comments and quoted loop examples must not establish the policy.

Keep cooperative yields and deliberate timer waits out of parallelization advice.
Recognize simple awaited Promise executors only when their single action schedules
the same resolver through an unshadowed bare `setTimeout` or `setImmediate`.
Use the same source mask as loop detection, rather than timer names in strings
or comments. Additional executor statements, alternate callbacks, chained
continuations and unresolved scheduler bindings remain reportable. Delay
calculations are not profiled; arbitrary retry and backpressure wrappers still
need contextual review.

Local timer-helper recognition requires a unique module-level function returning
a single timer Promise, with only resolution/cancellation and a source-proven local
abort handler. Indirect calls, helper rebinding, unknown callback work and
nonstandard signal types remain conservative.

Bounded worker recognition requires a shared cursor initialized before a
zero-argument async worker, an index claim before each job await, a capped
`Array.from` launch and an immediate `Promise.all` join. Check binding uses so an
escaped worker or reused cursor cannot borrow that exemption. Keep other awaits
in the same function or file eligible.

Terminal loop-await recognition requires a direct, semicolon-terminated call
followed only by straight-line calls and an unconditional return in the same
recognized function. An unlabeled break qualifies only when that function has
one lexical loop keyword and no switch. Keep functions containing `finally`,
conditional exits, labeled and nested-loop breaks, assignments and unsupported
expressions reportable. Retry and pagination names alone do not prove ordering.

Partial-success loop recognition requires an immediately preceding local zero
counter, an unconditional increment in the outer try, publication on that
catch-bound error before rethrowing it, and a matching return after the loop.
Counter and error references must stay unambiguous. Only awaits before the
increment gain the proof; nested loops/functions, deferred publications, early
control transfers and `finally` remain conservative. Remote admission or
rollback API names alone do not establish loop independence or required ordering.

Promise-stabilization recognition requires a local `let` snapshot, a do/while
body containing only assignment and await, and a strict identity recheck of the
same reference or zero-argument getter. The declaration and three loop uses
must be that snapshot's only references in the containing function. Preserve
advice for different getters, escaped bindings, extra work and neighboring loops;
protocol or callback names alone do not establish ordering.

### Rust panic-rule precision

`rust-unwrap` and `rust-expect` analyze production code. Inline `#[test]`, established namespaced test harnesses, and cfg branches limited to tests or explicit test-support features are excluded. Unknown feature alternatives and debug code remain production candidates. Targeted `#[allow(...)]` and `#[expect(...)]` lint attributes are explicit escape hatches for project-specific invariants; keep them attached to the intended scope.

The detector recognizes literal regexes, formatted regexes whose dynamic arguments all use `regex::escape`, regex capture group zero (including proven chained capture iterators), generated catalog lookups, catalog severity parsing, and direct UTF-8 reconstruction with an explicit byte-preservation rationale. Attached function `# Panics` contracts are treated as intentional panic policy, not as proof that calls cannot fail. Arbitrary expectation messages, dynamic regexes, optional or unchecked capture groups, and unproven runtime values remain reportable.
Panic policy may use outer line/block documentation or literal `doc` attributes,
with intervening multiline attributes. Computed documentation is not evaluated,
and policies do not extend into nested or neighboring functions.

Local flow proofs accept matching, uninvalidated `Option`/`Result` guards and
unconditional failure returns, including logging before returning. Supported
short-circuit conditions and direct same-scope `Some` assignments can establish
presence; terminal `break`/`continue` guards must exit the same direct loop body.
An exact standalone `is_none()` branch that initializes the same receiver to
`Some(...)` also proves fallthrough presence, not success of an inner `Result`.
Nonempty or singleton collection guards can prove direct element access and fresh
iteration, including guarded match arms, early-return `let Some` checks of
non-consuming first/last access, and presence-preserving reference adapters.
Nonempty `while` conditions reestablish collection presence at direct body entry,
including `pop_front`, but mutation or consumption before access invalidates it.
Fresh `split`/`rsplit` iterators have a first and last segment, even for empty text;
filtering, terminating splits, and previously consumed iterators do not gain this proof.
Mutation, shadowing, nested callbacks, filtering, and unknown indexing invalidate
collection proofs. First-character access after an exact character-count check and fresh
case-mapping iterators from locally established `char` values are also recognized.
`CString::new` accepts NUL-free literals and unambiguous root `const &str` literals;
dynamic values, ambiguous names, and unsupported literal escapes remain reportable.
These checks do not resolve arbitrary Rust types or infer safety from an
unconditional public module merely being named `test`.

Direct standard `format!` initializers can also establish an owned mutable String
for empty `writeln!` and simple literal-only output. Keep destination and binding
scope checks intact: custom writers, shadowed bindings, wrapped constructors,
unresolved formatting macros/imports and arbitrary `Display` values must not gain
this proof.

Keep lint allowances and expectations attached to the intended item or expression;
multiline attributes and their `reason` fields must not affect neighboring code.
Explicit unsafe-documentation policies propagate only through unambiguous declared
Rust modules; deny/forbid boundaries and unsupported module layouts remain conservative.
Unsafe-operation checks accept attached SAFETY/SAFE rationale on containing expressions,
including macro expressions, but do not inherit comments across completed statements or
reuse function Safety contracts as block rationale. Documented direct Box/Rc/Arc ownership
roundtrips are distinguished
from reconstruction of arbitrary raw pointers and unrelated custom APIs. Fresh
same-owner roundtrips may include compiler-checked trait-object unsizing; arbitrary
concrete-layout conversions do not gain that exemption.

### Rust repository-policy rules

Rust repositories with checked-in CI should run `cargo fmt --all -- --check`
or an equivalent direct `rustfmt --check`, and Clippy alongside their normal
Cargo build or test command. Code Buster accepts toolchain-qualified commands such as
`cargo +stable clippy`; it does not require the version-sensitive `pedantic`,
`nursery`, or beta lint sets.

SourceHut manifests at `.build.yml` and direct `.builds/*.yml` or
`.builds/*.yaml` paths participate in the same repository-policy checks.
Only executable task script scalars contribute command evidence; package lists,
environment values, task names, comments, and descriptive command examples do not.

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
Compiler-private library plugins require both explicit `rustc_private` metadata
and an unconditional matching feature gate in their actual crate root. A private
package or a pinned nightly toolchain alone is not an exemption.

Workspace analysis resolves production members from `members` and `exclude`
patterns while treating nested `[workspace]` manifests independently. Virtual
workspaces should declare the resolver matching their newest member edition.
Cargo root-only profile, patch, and replace tables must stay at the owning
workspace root, as must the effective lockfile. Non-virtual multi-package
workspaces should make CI scope explicit with `--workspace`, complete
`default-members`, or per-package commands.

Explicit inherited `package.publish`, `version`, and `description` fields resolve
through the owning workspace; local values take precedence. An unresolved inherited
publication policy is not evidence that a library is publishable.

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

Python file analysis uses Rayon's CPU-sized worker pool and merges results in
source order. Keep mutable scan state local to each file and repository-wide
matching outside the parallel phase. Use `RAYON_NUM_THREADS=1` as a control when
separating reduced analysis work from parallel speedups. Shared masked views are
initialized on demand per source context; do not introduce global source caches.

Generic rules share file-local raw and string-stripped lines while retaining
consumer-specific comment state and Rust test exclusions. Exact duplication
borrows normalized windows and paths; hash matches still require exact text,
language and scope equality. Preserve grouping caps and legacy fingerprint
material when changing this index.
Preserve Unicode whitespace and multiline comment state when adding normalization
fast paths. Keep regex prefilters conservative and apply them to the consumer's
processed lexical view.

Rust extraction advances scope/line state only to each candidate's start, not its
closing brace, so nested declarations remain visible. Keep enclosing-contract
caches file-local and discard them when the scope closes.

Rust source metrics may compact ASCII padding in a trailing blank suffix, but
must preserve every newline and the final non-newline line: unfinished literals
can count those lines as code. Never pass this shortened counter view back into
detector analysis or fingerprinting.

Regex-contract receiver lookups reuse the existing token/delimiter stream, not
semantic binding results. Preserve expression barriers, unmatched-delimiter
abstention and shadowing; file prefilters must be necessary conditions on masked
source, not raw text.

Rust simple-rule patterns search a full mask but remain line-local: exclude LF,
not Unicode whitespace, from whitespace spans. Emit only the first reportable
occurrence per rule/source line; a suppressed or proven-invariant call must not
hide later calls on that line. Reuse `RustFile`'s line starts for offset mapping.

Duplicate-window prehashes belong to one index's fixed randomized hash builder.
Hash equality is never sufficient: retain exact normalized-line, length, language
and scope comparisons. Do not use the prehash for published fingerprints or reuse
such keys across indexes.

Clean-code prefilters must be necessary conditions on the existing analysis view.
Share placeholder matching with exact-name qualification, retaining ASCII-only
case folding and Unicode decimal suffixes. Keep brace, comment and main-guard
tracking active on non-candidate lines. Do not narrow the declaration regex:
changing its non-overlapping match consumption can change later declarations.

Pass complete source text to shared string masking; do not allocate owned input
lines just to mask or rejoin them. Retain each consumer's lexical view and final
empty split line. Quoted-span batching must stop at delimiter/escape candidates
without splitting UTF-8, and preserve cooked/raw string state and CRLF behavior.
Python fixture guards must remain necessary conditions on the original source;
keep unrelated lines borrowed and preserve the existing fixture-padding contract.

Generic command scanning can borrow a line only when no comment-marker candidate
exists and its block-comment state is inactive. Preprocessor candidate guards
must still mask ordinary lines inside disabled branches. Collection guards must
use the existing processed view and keep the comma threshold per matched
collection, not per source line; separate small literals do not form one list.

Multiline numeric masks may borrow only under their existing unchanged-line state
guard. Keep owning shared-mask callers explicit with `into_owned`; numeric
consumers can borrow directly. Unquoted batching must stop at ASCII quote/slash
candidates and retain raw-prefix offsets, UTF-8 boundaries and all existing
multiline transitions.

Dart numeric analysis enables comment masking on the existing multiline lexer,
using its nested block depth. Other consumers keep their default view, which
preserves comments. Do not pass an already-masked Dart numeric view through the
legacy boolean comment stripper; it cannot represent nested comments.

Python capture-location storage is file-local; read group offsets only after a
successful match. Import prefilters must not skip scope or binding updates on
other lines. Credential prefilters must be necessary conditions on the existing
code view, including both scalar assignments and dictionary entries.

Python security candidate checks must use the view read by each matcher. SQL may
reuse code/stripped byte-length equality only while both are untrimmed and
`strip_quoted_strings` removes nonempty matches with the same `QUOTED_STRING` regex.
Keep complete archive matching (including spaced calls), receiver provenance and
safe filters; retain the string-preserving code view for f-string logging.

## Preparing a release

Add user-visible changes under `## Unreleased`, then prepare the Cargo package
version, lockfile, same-repository integration Action tag, and changelog heading together:

```sh
./tool/prepare-release.sh 0.10.0
```

Before pushing, repeat verification with the toolchain pinned in
`.github/workflows/release.yml`, currently Rust 1.88.0. Use `cargo +1.88.0`
for the Clippy, test, build, and package commands above; a clean run on a newer
local toolchain does not guarantee that the release toolchain accepts the code.

The script requires Python 3 and is idempotent for an already-prepared version.
It does not create a tag, push commits, or publish a release. Run the
verification commands above, commit the prepared sources, and dispatch the
release workflow from `main`. The workflow builds and smokes every native
artifact before publishing the crate through crates.io Trusted Publishing, then
publishes the GitHub release.
