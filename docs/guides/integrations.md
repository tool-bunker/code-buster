# CI and integrations

Publish Code Buster results through common CI and build-system formats.

Pin the Code Buster version in CI and run from the repository root so paths remain stable.

## JSON and NDJSON

```sh
cb summary --format json > code-buster.json
cb summary --format ndjson > code-buster.ndjson
```

JSON is the complete machine contract. NDJSON is useful for streaming consumers. Check the run status and processing diagnostics before accepting the findings array.

## SARIF and JUnit

```sh
cb summary --format sarif > code-buster.sarif
cb summary --format junit > code-buster.xml
```

Upload SARIF to code-scanning systems. Use JUnit where CI understands test-style failure reports.

## Code Climate

```sh
cb summary --format json | python3 tool/code_climate_report.py > code-climate.json
```

The converter consumes the stable JSON contract and emits deterministic Code Climate issue JSON.

## GitHub Actions

The repository contains `integrations/github/code-buster.yml` as a starting workflow. Compile or install a pinned `cb`, run the desired command, preserve its report artifact, and let explicit CI policy determine failure.

## Gradle and Maven

Use the supplied examples:

- `integrations/gradle/code-buster.gradle`
- `integrations/maven/code-buster-profile.xml`

Both call the external CLI rather than embedding analyzer internals, keeping the integration boundary stable.

## VS Code tasks

Copy or adapt `integrations/vscode/tasks.json` to expose common analysis commands from the editor.

## Exit codes

Operational errors and policy findings are distinct outcomes. Do not replace exit-code handling with a check for non-empty stdout. Archive the machine report when a CI job fails so coverage, diagnostics, and findings can be reviewed together.
