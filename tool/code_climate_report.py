#!/usr/bin/env python3
"""Adapt stable Code Buster JSON for Code Climate without coupling the CLI to it."""

import json
import sys


def main() -> int:
    report = json.load(sys.stdin)
    issues = []
    for finding in report.get("findings", []):
        severity = {"error": "critical", "warn": "major", "warning": "major"}.get(
            finding.get("severity"), "minor"
        )
        issues.append(
            {
                "type": "issue",
                "check_name": finding["code"],
                "description": finding["message"],
                "categories": ["Bug Risk"],
                "severity": severity,
                "fingerprint": finding["fingerprint"],
                "location": {
                    "path": finding["path"],
                    "lines": {
                        "begin": finding["line"],
                        "end": finding.get("endLine", finding["line"]),
                    },
                },
            }
        )
    json.dump(issues, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
