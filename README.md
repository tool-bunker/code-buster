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

## One command. A clearer codebase.

Run Code Buster from the root of any repository:

```sh
cb
```

That is enough to get a repository-wide summary. Code Buster points out
dependencies, duplication, complexity, hotspots, and possible drift so you and
your coding agents can reuse what already exists and keep the codebase easier to
understand as it grows.

<p align="center">
  <img src="website/assets/repository-overview.gif" width="612" alt="Code Buster summarizes a repository and identifies hotspots with one command">
</p>

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

## Is Code Buster a linter?

Not quite. A linter usually focuses on one language and local code issues. Code
Buster steps back and looks at the repository as a whole.

It can report lint-like issues, but it is mainly built to show:

- how files and modules are connected;
- what a change might affect;
- where code is duplicated or starting to drift;
- which parts of the repository need attention;
- when code bypasses an existing boundary, component, or design token.

Code Buster works alongside tools such as `dart analyze`, ESLint, Clang-Tidy,
and compiler diagnostics. It does not replace them.

<p align="center">
  <img src="website/assets/quality-workflow.gif" width="612" alt="Code Buster finds duplicated implementation blocks for review">
</p>

## Current Status

**Overall status: 0.2.0 release candidate.** The Dart implementation is the
canonical runtime and passes strict analysis, the complete test suite, native
compilation, documentation validation, self-analysis, and multi-repository
precision checks. 

The circles show current implementation depth and real-world validation. They
are a guide, not a guarantee.

| Language | Depth | Real-world validation |
| --- | :---: | :---: |
| Dart | ●●●●● | ●●●●● |
| C# | ●●●●○ | ●○○○○ |
| Java | ●●●●○ | ●○○○○ |
| Nim | ●●●●○ | ●○○○○ |
| Python | ●●●●○ | ●○○○○ |
| C/C++ and Objective-C | ●●●○○ | ●○○○○ |
| Go | ●●●○○ | ●○○○○ |
| JavaScript and TypeScript | ●●●○○ | ●○○○○ |
| Lua and Luau | ●●●○○ | ●○○○○ |
| SQL, PostgreSQL, and MySQL | ●●●○○ | ●○○○○ |
| Wren | ●●●○○ | ●○○○○ |
| CSS | ●●○○○ | ●○○○○ |
| HTML | ●●○○○ | ●○○○○ |
| Rust | ●●●○○ | ○○○○○ |
| Mojo | ●●●○○ | ○○○○○ |

**Depth** measures how much useful analysis is implemented. **Real-world
validation** measures testing against external repositories, including review
of false positives, missed findings, and the rule improvements that follow.

Help develop Code Buster by running it on real repositories and
[reporting what you find](https://github.com/tool-bunker/code-buster/issues/new/choose).
Even languages with high depth still need much more real-world testing. Reports
of false positives, missed problems, and confusing results are especially useful.

## Contributing

Open pull requests against `develop`. The `main` branch is reserved for
reviewed release changes and coordinated hotfixes. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution contract.