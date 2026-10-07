<h1>
<p align="center">
  <img src="assets/branding/code-buster.png" width="720" alt="Code Buster Symbol">
  <br>Code Buster
</h1>
  <p align="center">
    The AI Improver for code
    <br />
    <br />
    <a href="https://toolbunker.dev/codebuster/">Overview</a>
    ·
    <a href="https://toolbunker.dev/codebuster/docs/getting-started/installation">Installation</a>
    ·
    <a href="https://toolbunker.dev/codebuster/docs/">Documentation</a>
    ·
    <a href="CONTRIBUTING.md">Contributing</a>
  </p>
</p>

## Keep your AI agent grounded

Code Buster gives AI coding agents a deterministic, offline feedback loop they
can run while working. Context overload and hallucinations remain practical
constraints, so Code Buster examines individual files and relationships across
a repository to surface issues that prompts can miss.

It does not upload source code, call an AI provider, consume model tokens, or
make semantic changes on its own. The executable is `cb`; optional repository
configuration lives in `code-buster.toml`.

- 18 recognized source languages
- 450+ registered rules
- 7 report formats
- 0 required cloud services

## Quickstart

Install the native Apple Silicon macOS build with Homebrew:

```sh
brew install tool-bunker/tap/code-buster
cb version
```

Install a native Apple Silicon macOS or x86-64 Linux build with the verified
installer:

```sh
curl -fsSL https://toolbunker.dev/codebuster/install | sh
```

On x86-64 Windows PowerShell:

```powershell
irm https://toolbunker.dev/codebuster/install.ps1 | iex
```

When Dart 3.11 or newer is already installed:

```sh
dart pub global activate code_buster
cb version
```

Then run Code Buster from a repository root:

```sh
cb summary
```

Configuration is optional. Start with coverage in the summary, then use focused
commands such as `review`, `duplication`, `graph`, `dead`, `hotspots`, or
`inspect` for the question you need to answer.

Analysis caches live in the operating system's user-cache directory, not in the
analyzed repository. Use `--no-cache` for one-off runs or `--cache-dir PATH`
when a CI job or local workflow needs an explicit cache location.
Focused commands and `--only RULE` execute only the required analysis families.
Finding-family caches are reused independently, and `--verbose` JSON manifests
include pipeline and rule-family durations for performance diagnosis.

See the [installation guide](https://toolbunker.dev/codebuster/docs/getting-started/installation)
and [quickstart](https://toolbunker.dev/codebuster/docs/getting-started/quickstart)
for every supported path.

## What Code Buster finds

Code Buster combines file-level rules with repository-wide analysis. It reports:

- dependency cycles and architecture-policy violations;
- duplicated blocks, near-duplicate functions, and repeated patterns;
- unreachable production files and declarations;
- complexity growth, hotspots, and maintainability risks;
- correctness, reliability, security, accessibility, performance, and style findings;
- repository structure, source classification, framework, and design-system drift.

Findings can include a stable rule ID, severity, confidence, location,
rationale, remediation guidance, related files, and fingerprint. A finding is
evidence for review, not proof that the code is wrong.

## Use it with an AI coding agent

Make Code Buster part of the agent's working loop rather than waiting for a
final review:

1. Let the agent implement a focused change.
2. Run the narrowest relevant Code Buster command.
3. Have the agent evaluate relevant findings and iterate.
4. Review the resulting diff, run the project's tests, and exercise the changed
   behavior.

For a compact, repository-aware review signal without placing the whole
codebase in the model's context:

```sh
cb review --format json
```

Code Buster finds potential issues; the developer or agent decides what matters
and makes the fix.

## Language and framework support

Code Buster recognizes C and C++, Objective-C, C#, Dart, Rust, Mojo, Odin, Nim,
Python, JavaScript, TypeScript, Go, HTML, CSS, Java, Wren, SQL, and Lua/Luau.
Analysis depth and real-world validation vary by language. Flutter, React,
Svelte, PixiJS, and FastAPI are detected as framework profiles rather than
separate source languages.

See the current [language support matrix](https://toolbunker.dev/codebuster/docs/reference/languages).

## Reports and integrations

Available formats are text, JSON, NDJSON, Markdown, SARIF 2.1.0, Mermaid, and
JUnit XML. The repository also includes starting integrations for GitHub Actions,
Gradle, Maven, VS Code, and Code Climate conversion.

See the [command reference](https://toolbunker.dev/codebuster/docs/reference/commands),
[report reference](https://toolbunker.dev/codebuster/docs/reference/reports), and
[integration guide](https://toolbunker.dev/codebuster/docs/guides/integrations).

## Current status

Code Buster 0.8.0 is pre-1.0 and under active development. It substantially
reduces full-analysis time on large mixed-language and Python repositories while
expanding Rust safety analysis. Use it for local repository exploration,
focused AI context, and reviewing changes before handoff. Do not yet rely on it
as a blocking production quality gate; evaluate CI and report integrations with
explicit policy and preserved coverage.

## Development and contributing

Build the canonical Dart implementation from source:

```sh
dart pub get
dart compile exe bin/cb.dart -o build/cb
./build/cb version
```

Open pull requests against `main`. Keep branches short-lived; `main` is the
single long-lived branch and must remain releasable. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the complete contribution, verification,
and release contract.
