# Changelog

## Unreleased

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
