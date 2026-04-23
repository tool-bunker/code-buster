#!/usr/bin/env python3
"""Verify archived release evidence offline before publishing artifacts."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"release evidence invalid: {message}")


def main() -> int:
    precision = json.loads(
        (ROOT / "release/evidence/precision-benchmark.json").read_text()
    )
    if precision.get("schemaVersion") != 1 or not precision.get("passed"):
        fail("precision evidence did not pass")

    print("release evidence valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
