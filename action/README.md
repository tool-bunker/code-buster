# Code Buster Action

Run [Code Buster](https://github.com/tool-bunker/code-buster) on a checked-out repository and retain actionable findings, advisories, JSON/SARIF reports, and a GitHub job summary.

The root `action.yml` and implementation under `action/` belong to the Code Buster repository and use its release tags, starting with `v0.15.0`. Marketplace listing is optional and separate from using the Action.

## Use

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
    with:
      fetch-depth: 0
  - name: Review repository
    id: cb
    uses: tool-bunker/code-buster@v0.15.0
    with:
      advisory: 'true'
      fail-on-issues: 'true'
  - name: Retain reports even when the finding gate fails
    if: always() && steps.cb.outputs.report-directory != ''
    uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7
    with:
      name: code-buster
      path: ${{ steps.cb.outputs.report-directory }}
```

Pin a Code Buster release containing the Action, or its immutable commit SHA. Omit `version` to use that Action checkout's `Cargo.toml` package version; an explicit `version` selects a different published engine. There is no independent Action version or release repository.

## Behavior

- Downloads the requested published native CB archive and `SHA256SUMS`; rejects missing, ambiguous, or mismatched checksums before extraction or execution. Only the executable is extracted, and its reported version must match.
- Runs uncached `cb review` using the repository's normal configuration and supported-source discovery. It does not execute project code, install project dependencies, or include tests/vendor/examples by force.
- Saves complete JSON and SARIF 2.1.0 reports plus native stderr diagnostics. Capturing CB stdout supports the published engine independently of its optional `--output` behavior.
- Reports source files and code lines actually analyzed, not the whole repository's size. Unsupported/empty scans and incomplete or incompatible reports fail rather than looking clean.
- Fails on actionable findings when requested. Advisories stay visible as review evidence; severity is not used to infer actionable/advisory mode. Setup and analysis failures always fail, including in report-only mode.

Use `fail-on-issues: 'false'` for an initial evidence review before making a project blocking. Do not suppress findings merely to obtain a passing check.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | Action checkout's Cargo package version | Published engine version; `latest` and branches are rejected. Ignored with `executable`. |
| `path` | `.` | Scan directory inside the checked-out `GITHUB_WORKSPACE`; realpath escapes are rejected. |
| `executable` | unset | Explicit existing native CB binary for source self-analysis. No release download/checksum claim applies. |
| `changed-base` | unset | Git revision for changed-scope review; checkout needs that history. Omit for a full scan or repositories without Git. |
| `advisory` | `true` | Include advisory details. Totals remain visible regardless. |
| `fail-on-issues` | `true` | Fail after preserving valid reports when actionable findings exist. |

Boolean values must be `true` or `false`. Inputs are passed as argument arrays, never evaluated as shell code. There is deliberately no arbitrary shell-command/argument-string input.

## Outputs

`report-directory` is available after creating the output directory, including when a later step fails. Successful complete analysis also exports `json-path`, `sarif-path`, `actionable-count`, `advisory-count`, `files-scanned`, `code-lines`, and `cb-version`.

The reports and diagnostics live under `RUNNER_TEMP`; the downloaded executable is cleaned up. Report artifacts may contain repository paths, snippets, or other sensitive review evidence. Upload them only under the repository's access and retention policy. SARIF upload to GitHub code scanning is a separate consumer step requiring appropriate permissions; the Action itself needs no write token.

## Supported execution

The release installer supports the actual published targets: Linux x86-64, Apple Silicon macOS, and Windows x86-64. Its CI targets `ubuntu-24.04`, `macos-15`, and `windows-latest`. Other OS/architecture pairs fail explicitly. A supplied `executable` must be native to the runner.

The Action uses Node.js 24, which current GitHub-hosted runners provide. Self-hosted runners need a current Actions runner, compatible native runtime, `tar` capable of the platform archive, and outbound HTTPS access to GitHub release downloads. The code has no npm runtime dependencies.

## Source self-review

After building CB in its own repository:

```yaml
- uses: ./
  with:
    executable: ${{ github.workspace }}/target/release/cb
    advisory: 'true'
    fail-on-issues: 'true'
```

Use `cb.exe` on Windows. This checks the current source build, not a released substitute. Do not run a supplied untrusted PR executable in a privileged job or expose secrets to it. Normal `pull_request` workflows with read-only permissions are the intended boundary; do not combine `pull_request_target`, untrusted checkout, and privileged execution.

## Development and publication

From the Code Buster repository root:

```sh
npm --prefix action run check
npm --prefix action test
```

Repository CI exercises the local root Action (`uses: ./`) with real published binaries on all three supported runner targets and reviews each just-built CB executable. No target applications are built by the Action. Host-specific verification must be reported honestly; a macOS run is not Windows/Linux execution proof.

Normal CB release preparation updates the example Action reference to the same `vX.Y.Z` tag as the engine. The default engine version comes from the packaged Cargo manifest, so it needs no second version constant. Source CI deliberately supplies an already published engine for its download smoke test, while native self-review supplies the just-built executable.

Code Buster releases can also be selected for Marketplace publication when separately authorized; no extra repository, version series, or `v1` alias is needed.

## License

MIT; see the repository's root `LICENSE`.
