---
title: Commands
description: Reference for Code Buster command families and common global options.
---

Run `cb <command> --help` for the options supported by the installed version.

## Analysis

| Command | Purpose |
| --- | --- |
| `summary` | Repository overview, findings, language counts, coverage, and run manifest |
| `graph` | Dependency graph |
| `dead` | Unreachable production code |
| `duplication` | Repeated source blocks |
| `structure` | Repository and package structure |
| `clusters` | Related dependency clusters |
| `complexity` | Function complexity and cognitive complexity |
| `flags` | Feature flags and conditional behavior |
| `hotspots` | Concentrated change or quality risk |

## Investigation

| Command | Purpose |
| --- | --- |
| `inspect` | Explain one path's classification and analysis state |
| `related` | Find code related to a path |
| `why` | Explain why a path is reachable or selected |
| `path` | Find a dependency route between two paths |
| `explain` | Show rule rationale, limitations, and remediation |
| `rules` | List available rules and metadata |
| `config explain` | Show effective configuration and precedence |

## Quality and remediation

| Command | Purpose |
| --- | --- |
| `score` | Per-file and repository quality scores |
| `quality` | Quality-gate summary |
| `plan` | Prioritized remediation plan |
| `actions` | Action-oriented finding view |
| `review` | Review-oriented findings |
| `pr` | Pull-request-oriented changed analysis |
| `preview` | Preview selected files without creating analysis cache state |
| `fix` | Preview or apply supported safe fixes |

## Operations

| Command | Purpose |
| --- | --- |
| `init` | Create minimal repository configuration |
| `doctor` | Diagnose setup, discovery, and processing |
| `version` | Print the runtime version |
| `completions` | Generate shell completion data |

## Common options

Common options include `--root`, `--language`, `--format`, `--include-tests`, `--include-examples`, `--include-vendored`, `--all`, `--force`, and command-specific targets. Prefer `--format json` for automation and `--force` only when intentionally bypassing cache reuse.
