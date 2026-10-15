#!/usr/bin/env python3
"""Regression tests for reviewed changelog release notes."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_notes import extract_release_notes


class ReleaseNotesTests(unittest.TestCase):
    def test_extracts_only_requested_release_and_preserves_subsections(self) -> None:
        changelog = """# Changelog

## Unreleased

### Added

- Future change.

## 0.9.0

### Added

- First feature.

### Improved

- Better behavior.

## 0.8.1

### Improved

- Older behavior.
"""

        notes = extract_release_notes(changelog, "v0.9.0")

        self.assertEqual(
            notes,
            "### Added\n\n- First feature.\n\n### Improved\n\n- Better behavior.\n",
        )

    def test_rejects_missing_duplicate_and_empty_release_sections(self) -> None:
        invalid_changelogs = (
            "# Changelog\n\n## 0.8.1\n\n- Older.\n",
            "## 0.9.0\n\n- First.\n\n## 0.9.0\n\n- Duplicate.\n",
            "## 0.9.0\n\n## 0.8.1\n\n- Older.\n",
        )

        for changelog in invalid_changelogs:
            with self.subTest(changelog=changelog):
                with self.assertRaises(ValueError):
                    extract_release_notes(changelog, "0.9.0")


if __name__ == "__main__":
    unittest.main()
