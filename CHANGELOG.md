# Changelog

## Unreleased

## 0.8.1

### Improved

- Simplify repository source-role classification without changing precedence, and replace provably safe null assertions with explicit invariant checks.
- Add focused change-review findings for stale contract references, untested high-risk behavior, and new implementations duplicating unchanged repository behavior.
- Recognize `node-fetch` and `abort-controller` as redundant native capabilities only when `package.json` declares Node.js 18 or newer.
- Exclude standalone `#[test]` Rust functions from production findings and reject multiline method chains as trivial forwarding wrappers.
- Require call-shaped evidence for mixed boundary responsibilities and avoid treating explanatory member-access prose as commented-out code.

## 0.8.0

### Added

- Add Rust rules for undocumented unsafe blocks, mutable statics, raw ownership reconstruction, manual `Send` and `Sync` implementations, panic-capable exported FFI functions, blocking calls in async code, unbounded channels, and unpinned Cargo Git dependencies.

### Improved

- Parse Rust comments, literals, attributes, functions, and block ranges once for language rules and adapters, including nested comments and raw strings.
- Require an actual command-string switch before reporting Rust shell execution.
- Detect Cargo workspaces as Rust projects and record their declared `rust-version`.
- Recognize multiline Rust `SAFETY` rationales, mask raw strings in generic advisories, and classify conventional `benches` and test-helper sources outside production analysis.
- Classify conventional `test_suite` trees as tests, avoid Rust path fragments in same-value comparisons, and distinguish Rust macro interpolation and documented code examples from disabled source comments.
- Reduce large Python repository analysis times by sharing one coordinated rule pass and indexing monkey-patch replacement names once per file.
- Index function calls and references once for repository-wide YAGNI rules instead of rescanning every function for every private candidate.
- Precompute comment syntax by file while scanning comment-density evidence instead of rebuilding path expressions for every source character.
- Plan focused language analysis before indexing so `--only` scans skip unrelated rules, function extraction, and dependency graph construction.
- Reuse complete command findings before language parsing on warm cached runs while retaining content-hash invalidation and parser diagnostics on uncached inputs.
- Discover sources and nested `.gitignore` files in one traversal, reuse normalized path policies, and index selected languages by extension.
- Share one deterministic Python source index across coordinated rules, function extraction, and dependency graph construction.
- Precompute generic string-masked source lines once for repository rules instead of rescanning each file in every clean-code rule.
- Partition active, actionable, and advisory findings in one pass, reuse language indexes for summaries, and avoid rebuilding already enriched findings during report rendering.

## 0.7.5

### Improved

- Reduce large JavaScript and TypeScript repository analysis times by bounding function discovery, precomputing lexical context, prefiltering inline SQL candidates, and sharing comment scans.

## 0.7.4

### Added

- Add per-stage and per-rule-family timings to verbose run manifests.

### Improved

- Generate the embedded CLI and SARIF tool version from `pubspec.yaml` so release updates have one canonical version source.
- Plan focused commands and `--only` selections before rule execution, cache independent and per-source finding families, and reuse masked function sources across repository-wide YAGNI analyses.

## 0.7.3

### Added

- Detect Svelte projects and report async `onMount` cleanup, leaked global listeners and intervals, dynamic `{@html}` trust boundaries, unkeyed animation blocks, and browser globals in module scripts.
- Detect PixiJS projects and report PixiJS v8 migration hazards, unawaited application initialization, numeric ticker-delta assumptions, ticker listener lifecycle gaps, and display-object allocation inside frame loops.
- Add focused-change advisories for repeated caller-side guards around a shared project function and newly added single-use dependencies whose exact capability is already native.
- Detect Go derived contexts whose cancel function is discarded or never used.
- Detect Go SQL row iteration that omits the terminal `Rows.Err()` check.
- Detect JavaScript and TypeScript timers that execute string or template-literal source text.

### Improved

- Consolidate consecutive single-use forwarding functions into one maximal-chain finding across C++, C#, Dart, Go, Java, JavaScript, TypeScript, Python, and Rust.
- Keep individual YAGNI findings while adding file-level guidance when at least three findings from two rule families indicate concentrated speculative design.
- Analyze TypeScript correctness and security rules in one shared lexical pass instead of remasking every source for each registered rule.
- Remove the obsolete repository-hosted product site and recording sources now that canonical documentation and installer scripts are owned by `toolbunker.dev`.
- Round the README rule count to `450+` so routine rule additions do not require documentation churn.

## 0.7.2

### Added

- Detect single-use private functions that only forward unchanged arguments to one local target, while excluding reused wrappers, transformations, validation, overrides, comments, and string references.
- Detect private parameters that receive the same simple constant at three or more visible call sites, while excluding public APIs, overrides, varying or dynamic arguments, optional parameters, ambiguous names, and incomplete reference evidence.
- Detect optional callback customization hooks on private functions when three or more visible callers all use the fallback path, while excluding public APIs, overrides, supplied hooks, non-callback options, ambiguous names, and incomplete reference evidence.
- Detect used optional parameters on private functions when three or more visible callers always omit them, while excluding public APIs, overrides, supplied options, callback hooks, unused parameters, ambiguous names, and incomplete reference evidence.
- Detect private one-caller factories that only construct one fixed product with unchanged arguments, while excluding reused factories, transformations, lifecycle, validation, selection, decoration, and public composition boundaries.
- Detect configuration options supplied through inline objects by every visible caller but never read by the private implementation, while excluding dynamic, forwarded, destructured, computed, public, and incompletely resolved configuration.
- Validate the new YAGNI rules through C++, C#, Go, Java, TypeScript, Python, and Rust adapters, with language-aware visibility and parameter parsing and explicit metadata language contracts.

### Improved

- Store analysis caches in the operating system's user-cache directory instead of modifying analyzed repositories, with `--no-cache` for one-off runs and `--cache-dir` for explicit persistence.
- Move the canonical product, documentation, and native installer URLs to `toolbunker.dev/codebuster`.
- Treat nested Dart libraries outside `lib/src` as public package entry points so exported provider libraries and their implementations are not reported as dead files.
- Classify conventional `vendored` directories as third-party source and top-level `templates` trees as example scaffolds.
- Avoid sensitive-logging findings for non-secret object metadata and accept owned Dart sinks closed through a local alias.
- Exclude multiline function and constructor parameters from cross-language public mutable-state findings.


## 0.7.1

### Improved

- Reuse compiled regular expressions across analysis passes and refine repeated-traversal, public-state, policy-literal, and peer-file naming advisories to remove self-analysis noise.
- Describe single-use contracts explicitly as speculative extension points so coding agents can recognize premature abstraction.
- Add a shared semantic diff model and advisory checks for broad refactors, style drift, untested behavior changes, speculative option bundles, and declaration-heavy abstractions.
- Detect newly unused private declarations, single-caller forwarding wrappers, and disconnected symbol churn in focused diffs.
- Flag newly added APIs with three or more Boolean options before opaque mode combinations spread to callers.
- Accept standard universal-selector border-box resets while retaining CSS universal-selector findings for broad matching rules.
- Treat scalar processing and explicit data projections as ownership boundaries rather than feature envy, and keep parsed TOML, JSON, and SARIF values behind typed object boundaries.
- Replace avoidable null assertions across source discovery, CLI gates and graphs, reporting, plugins, analysis pipelines, metadata registries, result buckets, duplication indices, language adapters, and rule packs with checked values; centralize mandatory map lookups and numbered or named regular-expression captures behind invariant-reporting accessors; and recognize map lookups proven by matching key iteration or `containsKey` control flow.
- Tighten project-wide advisory precision by requiring cross-file policy evidence, excluding generic counters and private implementation models, recognizing projection factories, and excluding analyzer, rule-pack, visitor, rule-registration, and finding-emission infrastructure from domain-design heuristics.
- Add repository-local agent guidance and a rule-development skill covering semantic evidence, precision safeguards, cache-version contracts, regression design, verification, and user ownership of committed changes.
- Move canonical user documentation to `toolbunker.dev`, refresh the README around focused findings for developers and AI agents, and remove the duplicate repository documentation tree.


## 0.7.0


### Added

- Separate framework rule overlays from source-language registries, with detected Flutter and React profiles and framework-aware rule metadata.
- Detect one-method C#, Dart, Java, and TypeScript abstractions with one stateless implementation constructed once.
- Add conservative clean-code checks for public mutable state, commented-out code, placeholder names, mixed boundary responsibilities, repeated policy literals, local file naming outliers, changed public APIs without related tests, and changed-function complexity regressions.
- Add Flutter profile checks for immutable widget constructors, lazy lists, image caching, widget keys, build purity, async context safety, controller ownership, localization, assets, form validation, BLoC side effects, widget injection, and adaptive controls.
- Detect FastAPI projects and add 25 conservative checks for route contracts, authentication, transport security, request logging, database lifecycle, query bounds, background work, settings, module cohesion, and changed-route integration tests.

### Improved

- Preserve Dart production reachability through generated routers and other generated dependency bridges without analyzing generated files for findings.
- Honor root-anchored `.gitignore` patterns and retain Dart source under command-oriented `cmd/commands/build` directories.
- Require explicit untrusted-input provenance for Dart path-traversal hotspots instead of treating generic filename parameters as attacker-controlled.
- Recognize generated-by headers paired with “do not modify” provenance, including Drift versioned-schema outputs.
- Avoid listener-lifecycle advisories for collection values owned and disposed by Flutter hooks.
- Detect C# archive extraction paths derived from `ZipArchiveEntry.FullName` without a containment check, including local extraction wrappers.
- Recognize public Python packages in nested workspace `src` layouts when computing dead-file reachability.
- Parse PEP 695 generic function declarations without treating type parameters as part of the function name.
- Treat `None`, `null`, and `undefined` string sentinels as placeholders rather than hardcoded Python credentials.
- Accept deliberately class-qualified Python function names when the function is installed as a local monkey-patch replacement.
- Recognize top-level PEP 420 namespace packages as public Python dependency roots.
- Classify `tests-unit` directories as tests and `*_examples` directories as examples.
- Honor explicit Pylint and Ruff suppressions for equivalent Python style rules.
- Honor matching inline `# noqa` directives for Python import-placement findings.
- Avoid digit-grouping suggestions for SQL, where underscore-separated numeric literals are not portable.
- Exclude predominantly literal SQL `VALUES` data and archived SQL snapshots from duplicate-code findings.
- Infer neutral SQL files as MySQL only from repeated sibling syntax, while preserving explicitly named PostgreSQL files.
- Track Go loop scopes across nested blocks without reporting defers scoped by an immediately invoked function.
- Require explicit `net/http` client type evidence before treating generic Go `Do` methods as HTTP responses.
- Exclude leading license headers and dependency manifests from implementation comment-density findings.
- Avoid Go defer-in-loop findings when an unconditional return, break, continue, or goto prevents the next iteration.
- Exclude duplicated Go implementations selected by complementary single-tag build constraints.
- Require `os.O_CREATE` before treating a Go `OpenFile` mode as an effective creation permission.
- Recognize HTTP response bodies closed by a typed local helper.
- Ignore Java `serialVersionUID` values in digit-grouping advice because they are opaque serialization identifiers, not human-readable quantities.
- Avoid TypeScript security findings for `Function` constructors and `innerHTML` ternaries whose inputs are entirely static string literals.
- Exclude conventional JavaScript and TypeScript `.backup` source copies from production analysis.
- Recognize conventional JavaScript and TypeScript tooling directories at any workspace depth when evaluating console output and metadata parsing.
- Avoid AI prompt-injection hotspots for explicitly defensive quoted examples and for unrelated properties such as session message counts.
- Treat conventional development, playground, and benchmark trees as JavaScript/TypeScript tooling, and accept static HTML passed through explicit Trusted Types wrappers.
- Exclude conventional `.gen` JavaScript and TypeScript outputs, including generated TanStack Router route trees, from production findings.
- Recognize substantial formatted Babel JavaScript bundles from their emitted helper set, including ESM and CommonJS outputs.
- Allow intentional console output in executable Node.js entrypoints identified by their shebang.

## 0.6.0

### Added

- Add conservative C# advisories for data clumps, interface segregation pressure, refused inheritance, and middle-man delegation.
- Extend C# OOP analysis with strategy dispatch, state behavior, feature envy, service-locator, observer-notification, and message-chain advisories.
- Complete C# OOP parity with dominant-boundary bypass, repeated adapter-mapping, and sibling template-workflow advisories.
- Add conservative Java data-clump and middle-man delegation advisories.
- Detect Java interface-segregation pressure and rejected superclass operations.
- Add Java strategy-dispatch, state-behavior, feature-envy, and message-chain advisories.
- Detect distributed Java service-locator dependencies and repeated observer broadcasts.
- Complete Java OOP parity with dominant-boundary bypass, repeated constructor mapping, and sibling workflow advisories.
- Add the complete conservative TypeScript OOP advisory pack for design, behavior, collaboration, boundaries, and workflows.

### Improved

- Reduce Java noise for deliberately ignored empty catches, externally defined annotated signatures, and forwarding constructors.
- Ignore Java `ObjectInputStream` imports until production code actually uses the deserialization type.
- Exclude control-flow calls such as returned decorator callbacks from TypeScript data-clump declarations.
- Analyze TypeScript arrow-property methods across the OOP advisory pack.

## 0.5.0

### Added

- Detect direct Dart implementation access that bypasses a dominant factory, facade, repository, or proxy boundary.
- Identify repeated Dart parameter groups and repeated callable variant dispatch as value-object and strategy candidates.
- Detect Dart interface-segregation pressure and repeated mutable lifecycle-state behavior.
- Detect repeated Dart object translations and near-identical sibling override workflows as adapter and template-method candidates.
- Detect Dart feature envy and distributed service-locator dependencies as responsibility and dependency-ownership advisories.
- Detect repeated Dart observer broadcasts and deep collaboration message chains.
- Detect rejected Dart superclass operations and predominantly forwarding middle-man classes.

## 0.4.0

### Added

- Add Odin discovery, local package graphs, procedure extraction, and focused correctness and memory-safety rules.
- Detect uniform repeated Flutter `SizedBox` gaps that can use `Row.spacing` or `Column.spacing`.
- Detect Python Requests calls that explicitly disable TLS certificate verification.

### Improved

- Resolve every branch of conditional Dart imports and exports so platform-specific implementations remain reachable in dependency graphs.
- Classify conventional Dart protobuf outputs as generated source.
- Require an established Flutter shared component to dominate direct framework-control usage before reporting bypasses.
- Recognize `*-examples` directories as example source.
- Improve Python import graphs, package reachability, type-only imports, symbolic secret assignments, and explicitly non-security hash usage.
- Execute registered Go findings in repository results, recognize conventional `testenv` packages, detect modern world-writable file modes, and avoid treating non-shell `-c` invocations as shell injection boundaries.
- Exclude Go declaration and interface documentation from implementation-comment density advisories.

## 0.3.0

- Add checksum-verified native installers and a channel-aware `cb update` command.
- Add Rust module graphs and focused correctness, safety, security, and test-boundary analysis.
- Add Mojo import graphs, function extraction, current-syntax migration checks, and raises-contract analysis.
- Resolve Dart multi-package workspace imports and remove large false dead-file floods.
- Add repeated runtime-bootstrap detection for Dart, Cargo, Go, .NET, Maven, and Gradle tests.
- Reuse one compiled Code Buster executable across process-based tests and CI verification.
- Complete real-world C#, Java, and TypeScript validation across 45 external repositories.
- Improve C#, Java, Rust, and TypeScript precision for test code, secrets, cryptography, SQL, interop, generated sources, and conditional compilation.
- Make advisory analysis honor C# namespace policy and exclude API documentation from implementation-comment density.
- Mark C#, Java, and JavaScript/TypeScript real-world validation as five out of five.

## 0.2.0

- Add project-level Flutter, HTML, and CSS UI consistency analysis.
- Detect established Flutter component bypasses and repeated design implementations.
- Add focused Java reliability, performance, and maintainability rules.
- Add scan-friendly color output for Git history hotspots.
- Replace the generated documentation site with canonical GitHub Markdown and a static project homepage.
- Add reproducible Terminalizer demonstrations and zero-build GitHub Pages deployment.

## 0.1.0

- Introduce the `cb` command-line interface for deterministic repository analysis.
- Add architecture, dependency, duplication, complexity, security, style, and quality analysis.
- Support Dart, C++, C#, Go, Java, JavaScript, Lua, Nim, Python, SQL, and Wren projects.
- Add configurable rule policies, baselines, caching, safe fixes, and machine-readable reports.
- Provide GitHub Actions, Gradle, Maven, and Visual Studio Code integrations.
