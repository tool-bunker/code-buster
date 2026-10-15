#!/usr/bin/env python3
"""Extract one reviewed release section from CHANGELOG.md."""

from __future__ import annotations

import argparse
from pathlib import Path


def extract_release_notes(changelog: str, requested_version: str) -> str:
    version = requested_version.removeprefix("v")
    heading = f"## {version}"
    lines = changelog.splitlines()
    matches = [index for index, line in enumerate(lines) if line.rstrip() == heading]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one {heading!r} heading, found {len(matches)}"
        )

    start = matches[0] + 1
    end = next(
        (
            index
            for index in range(start, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    notes = "\n".join(lines[start:end]).strip()
    if not notes:
        raise ValueError(f"release section {heading!r} has no notes")
    return f"{notes}\n"


def main() -> None:
    project_dir = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="release version, with or without a v prefix")
    parser.add_argument("output", type=Path, help="destination Markdown file")
    parser.add_argument(
        "--changelog",
        type=Path,
        default=project_dir / "CHANGELOG.md",
        help="changelog to read (default: repository CHANGELOG.md)",
    )
    arguments = parser.parse_args()

    try:
        notes = extract_release_notes(arguments.changelog.read_text(), arguments.version)
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
    arguments.output.write_text(notes)
    print(f"Extracted release notes for {arguments.version} to {arguments.output}.")


if __name__ == "__main__":
    main()
