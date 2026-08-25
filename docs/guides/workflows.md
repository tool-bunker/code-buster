# Analysis workflows

Apply Code Buster views to exploration, review, remediation, and baselines.

Code Buster commands are repository views over shared discovery, parsing, graph, rule, and reporting stages. Choose the narrowest view that answers the current question.

## Understand an unfamiliar repository

```sh
cb summary
cb structure
cb graph
cb clusters
cb hotspots
```

Start with coverage in `summary`. Use `structure` and `clusters` for package shape, `graph` for dependency wiring, and `hotspots` for concentrated risk.

## Investigate dependencies

```sh
cb related path/to/file
cb why path/to/file
cb path source/file target/file
cb dead
```

`related` ranks neighboring code, `why` explains reachability, `path` finds a dependency route, and `dead` reports production code unreachable from configured or inferred entry points.

## Review a change

```sh
cb review
cb pr
cb preview
```

Use changed-file analysis for pull requests and local work. Coverage and the run manifest record what was selected and whether processing completed cleanly; a short report without complete coverage is not equivalent to a clean repository.

## Plan remediation

```sh
cb complexity
cb duplication
cb score
cb quality
cb plan
cb actions
```

Complexity and duplication provide focused evidence. Scores and quality gates summarize policy. Plans and actions prioritize remediation without rewriting source automatically.

## Use Code Buster with AI coding assistants

Code Buster can give an AI coding assistant a compact, repository-aware review signal without placing large amounts of source code into the model's context. Run it after an AI makes a change, or periodically during a longer task, to catch duplicate functions, repeated blocks, dependency problems, architecture drift, and other common issues before they accumulate.

```sh
cb review --format json
cb duplication --format json
cb actions --format json
```

Pass the relevant findings—not necessarily the entire report—to the assistant and ask it to explain the evidence before proposing a change. Newer models can often make a useful decision from Code Buster's structured results while using substantially less context than a repository-wide integration.

Code Buster does not make AI-generated code correct by itself. Models vary: one may apply a recommendation blindly, another may ignore an important finding, and neither Code Buster nor the model knows your complete product intent. A reported duplication may be deliberate, a suggested abstraction may be worse than repetition, and a clean report does not prove that behavior is correct.

Treat the workflow as a review loop:

1. Let the assistant make a focused change.
2. Run the narrowest relevant Code Buster command.
3. Ask the assistant to evaluate each finding against the intended behavior.
4. Review the proposed remediation and resulting diff yourself.
5. Run the project's tests and exercise the changed behavior.

Code Buster has been used successfully as feedback for AI-assisted development, particularly for identifying duplication and recurring implementation risks. It improves the evidence available to the model; it does not remove the developer from design, verification, or accountability.

## Baselines and reproducibility

Use stable finding fingerprints and machine reports to compare reviewed runs. Keep repository configuration, tool version, source revision, selected coverage, and processing diagnostics with any baseline. Never treat missing or partial analysis as zero findings.

## Safe fixes

`cb fix` previews conservative whitespace and supported mechanical changes. Review the preview before applying it. Semantic remediation remains a source change owned by the developer because rule evidence cannot prove the intended design.
