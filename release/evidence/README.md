# Release evidence

These files are reviewed evidence for the next release candidate:

- `precision-benchmark.json` records exact labelled repository-local fixture precision and recall.

`python3 tool/release_evidence.py` validates the schema and pass status without network access. Regenerate evidence only after intentionally rerunning the precision benchmark and reviewing changes.
