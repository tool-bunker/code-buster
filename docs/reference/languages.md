# Language support

Current analysis depth and testing status by language family.

Implementation depth and real-world validation are tracked separately. **High**, **Moderate**, and **Foundational** describe analysis depth; they do not mean every construct is understood.

| Language | Depth | Testing status | Main capabilities |
| --- | --- | --- | --- |
| Dart | High | Done | Analyzer AST, package-aware graph, callables, broad rules, self-hosting |
| C# | High | Needs more testing | Project-aware graph plus correctness, reliability, security, and style rules |
| Java | High | Needs more testing | Packages, resources, exceptions, concurrency, SQL, cryptography, and cycles |
| Nim | High | Needs more testing | Dedicated parser, complete rule-pack wiring, and focused regressions |
| Python | High | Needs more testing | Imports, callables, graph analysis, and broad rules |
| C, C++, Objective-C | Moderate | Needs more testing | Dialect gating, includes, callables, safety, and modernization rules |
| Go | Moderate | Needs more testing | `go.mod` imports, methods, test classification, reliability, and security |
| JavaScript, TypeScript | Moderate | Needs more testing | Module graph, callables, frontend, Node.js, security, and TS checks |
| Lua, Luau | Moderate | Needs more testing | Module and callable extraction with correctness, runtime, and style checks |
| SQL dialects | Moderate | Needs more testing | Dialect-aware statements, correctness, safety, and maintainability |
| Wren | Moderate | Needs more testing | Imports, callables, and a dedicated rule pack |
| CSS | Foundational | Needs more testing | Discovery plus targeted structural and style checks |
| HTML | Foundational | Needs more testing | Discovery, embedded scripts, correctness, and style checks |

Use `languages = ["auto"]` for manifest and source-based detection, or list languages explicitly in `code-buster.toml`. Use `cb inspect <path>` when an extension, generated marker, or repository profile produces unexpected classification.

Unsupported source remains visible in the coverage ledger. Code Buster does not silently treat unsupported files as analyzed.
