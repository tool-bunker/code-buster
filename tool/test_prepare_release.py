#!/usr/bin/env python3
"""Behavioral tests for preparing Cargo and same-repository Action releases."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


class PrepareReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        (self.project / "tool").mkdir()
        shutil.copyfile(PROJECT / "tool/prepare-release.sh", self.project / "tool/prepare-release.sh")
        self.integration = self.project / "integrations/github/code-buster.yml"
        self.integration.parent.mkdir(parents=True)
        # Keep the real consumer stanza while fixing its previous release ref,
        # so these fixtures remain meaningful after later release preparations.
        integration, ref_count = re.subn(
            r"(?m)^        uses: tool-bunker/code-buster@[^ \t\r\n]+$",
            "        uses: tool-bunker/code-buster@v0.14.5",
            (PROJECT / "integrations/github/code-buster.yml").read_text(),
        )
        self.assertEqual(ref_count, 1, "consumer must expose one Code Buster Action reference")
        self.initial_integration = integration
        self.integration.write_text(integration)
        (self.project / "Cargo.toml").write_text(
            '[package]\nname = "code-buster"\nversion = "0.14.5"\n'
        )
        (self.project / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "code-buster"\nversion = "0.14.5"\n'
        )
        (self.project / "CHANGELOG.md").write_text(
            '# Changelog\n\n## Unreleased\n\n### Fixed\n\n- Reviewed fix.\n'
        )
        self.bin = self.project / "bin"
        self.bin.mkdir()
        # Package validation is Cargo's responsibility. These tests isolate the
        # file synchronization contract without building or fetching packages.
        cargo = self.bin / "cargo"
        cargo.write_text('#!/bin/sh\n[ "$1" = metadata ]\n')
        cargo.chmod(0o755)

    def prepare(self, version: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(self.project / "tool/prepare-release.sh"), version],
            env={**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_updates_real_integration_action_ref_and_release_files(self) -> None:
        result = self.prepare("0.15.0-rc.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.integration.read_text(),
            self.initial_integration.replace(
                "        uses: tool-bunker/code-buster@v0.14.5\n",
                "        uses: tool-bunker/code-buster@v0.15.0-rc.1\n",
            ),
        )
        for name in ("Cargo.toml", "Cargo.lock"):
            self.assertIn('version = "0.15.0-rc.1"', (self.project / name).read_text())
        self.assertIn("## Unreleased\n\n## 0.15.0-rc.1", (self.project / "CHANGELOG.md").read_text())

    def test_prepares_the_initial_main_action_reference(self) -> None:
        self.integration.write_text(
            self.initial_integration.replace(
                "tool-bunker/code-buster@v0.14.5",
                "tool-bunker/code-buster@main",
            )
        )
        result = self.prepare("0.15.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.integration.read_text(),
            self.initial_integration.replace(
                "tool-bunker/code-buster@v0.14.5",
                "tool-bunker/code-buster@v0.15.0",
            ),
        )

    def test_prepared_release_is_idempotent(self) -> None:
        result = self.prepare("0.15.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        paths = [
            self.project / "Cargo.toml",
            self.project / "Cargo.lock",
            self.project / "CHANGELOG.md",
            self.integration,
        ]
        before = {path: path.read_bytes() for path in paths}
        repeated = self.prepare("0.15.0")
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual({path: path.read_bytes() for path in paths}, before)

    def test_accepts_crlf_checked_out_release_files(self) -> None:
        paths = [
            self.project / "Cargo.toml",
            self.project / "Cargo.lock",
            self.project / "CHANGELOG.md",
            self.integration,
        ]
        for path in paths:
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        result = self.prepare("0.15.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.integration.read_bytes(),
            self.initial_integration.replace(
                "tool-bunker/code-buster@v0.14.5",
                "tool-bunker/code-buster@v0.15.0",
            ).encode(),
        )
        for path in paths:
            self.assertNotIn(b"\r", path.read_bytes())

    def test_rejects_missing_or_duplicate_action_refs_before_any_writes(self) -> None:
        original = self.integration.read_text()
        action_ref = "        uses: tool-bunker/code-buster@v0.14.5\n"
        invalid = {
            "missing": original.replace(action_ref, ""),
            "standalone repository": original.replace(
                action_ref, "        uses: tool-bunker/code-buster-action@v1\n"
            ),
            "duplicate": original + "\n" + action_ref,
            "commented duplicate": original + "\n" + action_ref.rstrip("\n") + " # release\n",
            "different refs": original + "\n        uses: tool-bunker/code-buster@main\n",
        }
        names = ("Cargo.toml", "Cargo.lock", "CHANGELOG.md")
        before = {name: (self.project / name).read_bytes() for name in names}
        for label, consumer in invalid.items():
            for newline in ("\n", "\r\n"):
                with self.subTest(consumer=label, newline=repr(newline)):
                    consumer_bytes = consumer.replace("\n", newline).encode()
                    self.integration.write_bytes(consumer_bytes)
                    result = self.prepare("0.15.0")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("one Code Buster Action reference", result.stderr)
                    self.assertEqual(self.integration.read_bytes(), consumer_bytes)
                    for name in names:
                        self.assertEqual((self.project / name).read_bytes(), before[name])


if __name__ == "__main__":
    unittest.main()
