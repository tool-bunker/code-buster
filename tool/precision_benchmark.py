#!/usr/bin/env python3
"""Reject precision and recall regressions against reviewed labelled findings."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", nargs="?", type=Path, default=ROOT / "test/fixtures/mixed_realistic")
    parser.add_argument("--output", type=Path, default=ROOT / "build/precision-benchmark.json")
    parser.add_argument(
        "--executable",
        type=Path,
        default=Path(os.environ.get("CODE_BUSTER_TEST_EXECUTABLE", ROOT / "build/cb")),
    )
    args = parser.parse_args()
    fixture = args.fixture.resolve()
    executable = args.executable.resolve()
    if not executable.is_file():
        raise SystemExit(f"Code Buster executable not found: {executable}")
    labels = json.loads((fixture / "precision_expectations.json").read_text())
    started = time.monotonic()
    process = subprocess.run(
        [str(executable), "summary", "--root", str(fixture), "--format", "json", "--verbose"],
        capture_output=True,
        text=True,
        check=False,
    )
    seconds = round(time.monotonic() - started, 3)
    if process.returncode != 0:
        raise SystemExit(process.stderr or f"cb exited {process.returncode}")
    report = json.loads(process.stdout)
    actual = {(item["code"], item["path"], item["line"]) for item in report["findings"]}
    accepted = {(item["code"], item["path"], item["line"]) for item in labels["accepted"]}
    rejected = labels.get("rejected", [])
    true_positives = len(actual & accepted)
    false_positives = len(actual - accepted)
    false_negatives = len(accepted - actual)
    rejected_hits = [item for item in rejected if any(
        finding[0] == item["code"] and finding[1] == item["path"]
        for finding in actual
    )]
    precision = true_positives / (true_positives + false_positives) if actual else 1.0
    recall = true_positives / (true_positives + false_negatives) if accepted else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    selected = report["manifest"].get("selectedFiles", [])
    lines = sum(len((fixture / relative).read_text(errors="replace").splitlines()) for relative in selected)
    result = {
        "schemaVersion": 1,
        "fixture": str(fixture.relative_to(ROOT)) if fixture.is_relative_to(ROOT) else str(fixture),
        "truePositives": true_positives,
        "falsePositives": false_positives,
        "falseNegatives": false_negatives,
        "rejectedHits": rejected_hits,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "findingsPerKloc": round(len(actual) / max(lines, 1) * 1000, 2),
        "sourceLines": lines,
        "seconds": seconds,
        "passed": false_positives == 0 and false_negatives == 0 and not rejected_hits,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(args.output)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
