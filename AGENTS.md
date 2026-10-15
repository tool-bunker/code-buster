# AGENTS.md
- For rule work, read `.agents/skills/code-buster-rule-development/SKILL.md` before editing.
- Reuse existing parsers, masks, source classifiers, metadata patterns, and cached regular expressions; never add repository-specific exceptions.
- Keep changes explicit and reviewable; commit only work the user can understand, explain, and confidently own.
- From `code-buster/`, update rule versions and contracts, then run formatting, Clippy, tests, packaging, native smoke checks, and fresh self-analysis.
