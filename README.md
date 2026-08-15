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
    <a href="documentation">Documentation</a>
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

## Current Status

**Overall status: 0.1.0 release candidate.** The Dart implementation is the
canonical runtime and passes strict analysis, the complete test suite, native
compilation, documentation validation, self-analysis, and multi-repository
precision checks. Publishing and the `v0.1.0` tag remain pending; see
[Release readiness](RELEASE_READINESS.md).

Language status describes the current analysis depth. Testing status is tracked
separately and remains conservative until a language has received extensive
real-repository validation:

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

Code Buster requires Dart 3.11 or newer.

```sh
dart pub get
dart compile exe bin/cb.dart -o build/cb
./build/cb version
```

Install the local checkout with `../install-code-buster.sh`.