<h1>
<p align="center">
  <img src="assets/branding/code-buster.png" width="720" alt="Code Buster Symbol">
  <br>Code Buster
</h1>
  <p align="center">
    Multi-language repository architecture and static-analysis CLI
    <br />
    <br />
    <a href="#about">About</a>
    ·
    <a href="#install">Installation</a>
    ·
    <a href="#currentstatus">Current Status</a>
    ·
    <a href="docs/README.md">Documentation</a>
    ·
    <a href="CONTRIBUTING.md">Contributing</a>
  </p>
</p>

## About

Code Buster reports dependency wiring, dead code, cycles, duplication,
complexity, architecture-policy violations, feature flags, security and style
heuristics, quality scores, and remediation plans.

This directory contains the canonical Dart implementation. Its executable is
`cb`, its configuration file is `code-buster.toml`, and the workspace installer
builds it from local source. 

## Is Code Buster a linter?

Not primarily. Code Buster includes lint-like correctness, security, and style
findings, but its main scope is the repository rather than one source file. It
builds views of dependencies, module boundaries, cycles, dead code, duplication,
complexity, hotspots, and related files across supported languages.

A language-native linter usually has deeper knowledge of one language and
reports local syntax, type, correctness, and style problems. Code Buster uses
cross-file and cross-language evidence to answer broader questions such as:

- How is this repository connected?
- What might a change affect?
- Where are responsibilities duplicated or drifting?
- Which files or modules deserve investigation first?
- Is code bypassing an established architecture, component, or design token?

The tools are complementary. Continue using analyzers and linters such as
`dart analyze`, ESLint, Clang-Tidy, or language-specific compiler diagnostics.
Code Buster does not replace them.

| | Language linter | Code Buster |
| --- | --- | --- |
| Primary scope | A file, declaration, or expression | A repository and its relationships |
| Strongest evidence | Language syntax, types, and semantics | Dependency graphs, repeated structures, and cross-file patterns |
| Typical output | Direct diagnostics for a language | Repository views, advisory findings, and investigation paths |
| Language depth | Deep knowledge of one language | Mixed-language analysis with depth varying by language |
| Main use | Enforce established language rules | Understand unfamiliar code and guide human or AI-assisted changes |

### What is the aim?

The aim is to support the full change loop for developers and AI coding agents:
understand the repository before editing, stay within its existing structures
while editing, and inspect the result afterwards. An AI agent can run Code
Buster against its own changes to find possible duplication, architecture
violations, component drift, dead code, and other issues before handing work
back for review.

Code Buster also helps keep repositories organized by making dependencies,
boundaries, repeated implementations, and concentrated complexity visible over
time. It should surface evidence and possible drift, not claim certainty that
static analysis cannot provide. Before version 1.0.0, use it primarily for local
investigation and non-blocking evaluation rather than as a production release
gate.

## Current Status

**Overall status: 0.2.0 release candidate.** The Dart implementation is the
canonical runtime and passes strict analysis, the complete test suite, native
compilation, documentation validation, self-analysis, and multi-repository
precision checks. 

Language status describes the current analysis depth. 

| Language | Status | Testing status | Current analysis evidence |
| --- | --- | --- | --- |
| Dart | **High** | **Done** | Analyzer AST, package-aware dependency graphs, function extraction, broad rule coverage, and self-hosting validation |
| C# | **High** | **Needs more testing** | Dedicated adapter suite with project-aware graph handling and broad correctness, reliability, security, and style rules |
| Java | **High** | **Needs more testing** | Dedicated adapter suite and focused regression suites for resources, exceptions, concurrency, SQL, cryptography, and package cycles |
| Nim | **High** | **Needs more testing** | Dedicated parser and rule packs with complete catalog wiring and focused regression coverage |
| Python | **High** | **Needs more testing** | Import and function extraction, graph analysis, dedicated adapter tests, and broad rule coverage |
| C/C++ and Objective-C | **Moderate** | **Needs more testing** | Dialect-aware source gating, includes, callable extraction, and targeted safety and modernization rules |
| Go | **Moderate** | **Needs more testing** | `go.mod`-aware imports, methods and functions, test classification, and focused reliability and security suites |
| JavaScript and TypeScript | **Moderate** | **Needs more testing** | Module graph and function extraction with frontend, Node.js, security, and TypeScript-specific checks |
| Lua and Luau | **Moderate** | **Needs more testing** | Module and callable extraction with targeted correctness, runtime, and style checks |
| SQL, PostgreSQL, and MySQL | **Moderate** | **Needs more testing** | Dialect-aware statement analysis with correctness, safety, and maintainability checks |
| Wren | **Moderate** | **Needs more testing** | Import and callable extraction with a dedicated rule pack and adapter regressions |
| CSS | **Foundational** | **Needs more testing** | Tested source discovery and targeted structural and style checks |
| HTML | **Foundational** | **Needs more testing** | Tested source discovery, embedded-script handling, and targeted correctness and style checks |

**High**, **Moderate**, and **Foundational** describe implementation depth, not
test completion. **Done** means the language has extensive unit, integration,
self-hosting, and external-repository validation. **Needs more testing** means
the existing automated coverage passes, but broader real-world validation is
still required.

## Installation

Building Code Buster from source requires Dart 3.11 or newer. Native packages do not require Dart.

### Homebrew (macOS)

Install the native Apple Silicon build from the Tool Bunker tap:

```sh
brew install tool-bunker/tap/code-buster
cb version
```

### Install script (macOS and Linux)

Install the native Apple Silicon macOS or x86-64 Linux build:

```sh
curl -fsSL https://codebuster.toolbunker.dev/install | sh
```

### Windows

Install the native x86-64 build from PowerShell:

```powershell
irm https://codebuster.toolbunker.dev/install.ps1 | iex
```

Both scripts verify the release archive against the published SHA-256 checksum
and install under the current user's `~/.local/bin` directory.

### Dart and Flutter

Install the published package when Dart 3.11 or newer is already available:

```sh
dart pub global activate code_buster
cb version
```

Ensure `$HOME/.pub-cache/bin` is on `PATH` when using Dart global activation.

### Local source build

```sh
dart pub get
dart compile exe bin/cb.dart -o build/cb
./build/cb version
```

Install the local checkout with `../install-code-buster.sh`.

## Contributing

Open pull requests against `develop`. The `main` branch is reserved for
reviewed release changes and coordinated hotfixes. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution contract.