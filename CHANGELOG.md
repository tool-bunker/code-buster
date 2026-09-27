# Changelog

## Unreleased


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
