#!/bin/sh
# Update the Cargo package version and promote Unreleased changelog notes.
set -eu

usage() {
  printf '%s\n' 'usage: ./tool/prepare-release.sh <version>' >&2
  printf '%s\n' 'example: ./tool/prepare-release.sh 0.10.0' >&2
}

if [ "$#" -ne 1 ]; then
  usage
  exit 64
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'error: Python 3 is required' >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  printf '%s\n' 'error: Cargo is required' >&2
  exit 1
fi

version=$1
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

python3 - "$project_dir/Cargo.toml" "$project_dir/Cargo.lock" "$project_dir/CHANGELOG.md" "$project_dir/integrations/github/code-buster.yml" "$version" <<'PY'
from pathlib import Path
import re
import sys

manifest_path = Path(sys.argv[1])
lock_path = Path(sys.argv[2])
changelog_path = Path(sys.argv[3])
integration_path = Path(sys.argv[4])
version = sys.argv[5]

semver = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
    r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
if not semver.fullmatch(version):
    raise SystemExit(f"error: invalid semantic version: {version}")

manifest = manifest_path.read_text()
package = re.search(r"(?ms)^\[package\]\n(?P<body>.*?)(?=^\[|\Z)", manifest)
if package is None:
    raise SystemExit("error: Cargo.toml has no [package] table")
version_matches = list(re.finditer(r'(?m)^version = "([^"]+)"$', package.group("body")))
if len(version_matches) != 1:
    raise SystemExit("error: Cargo.toml [package] must contain exactly one version")
current_version = version_matches[0].group(1)
absolute_start = package.start("body") + version_matches[0].start(1)
absolute_end = package.start("body") + version_matches[0].end(1)
updated_manifest = manifest[:absolute_start] + version + manifest[absolute_end:]

lock = lock_path.read_text()
lock_pattern = re.compile(
    r'(\[\[package\]\]\nname = "code-buster"\nversion = ")[^"]+("\n)'
)
updated_lock, lock_count = lock_pattern.subn(rf"\g<1>{version}\2", lock, count=1)
if lock_count != 1:
    raise SystemExit("error: Cargo.lock has no code-buster package entry")

changelog = changelog_path.read_text()
release_heading = re.compile(rf"(?m)^## {re.escape(version)}[ \t]*$")
release_matches = list(release_heading.finditer(changelog))
if len(release_matches) > 1:
    raise SystemExit(f"error: CHANGELOG.md has duplicate {version} headings")
if release_matches:
    if current_version != version:
        raise SystemExit(
            f"error: CHANGELOG.md already has {version}, but Cargo.toml has {current_version}"
        )
    updated_changelog = changelog
else:
    unreleased_matches = list(re.finditer(r"(?m)^## Unreleased[ \t]*$", changelog))
    if len(unreleased_matches) != 1:
        raise SystemExit("error: CHANGELOG.md must contain one ## Unreleased heading")
    unreleased = unreleased_matches[0]
    body_start = unreleased.end()
    next_heading = re.search(r"(?m)^##[ \t]+", changelog[body_start:])
    body_end = len(changelog) if next_heading is None else body_start + next_heading.start()
    body = changelog[body_start:body_end]
    if not body.strip():
        raise SystemExit("error: CHANGELOG.md Unreleased section has no notes")
    updated_changelog = (
        changelog[:unreleased.start()]
        + "## Unreleased\n\n"
        + f"## {version}"
        + body
        + changelog[body_end:]
    )

crate_install_pattern = re.compile(
    r"(cargo install code-buster --version )[^ \r\n]+( --locked)"
)

def update_crate_install(path):
    updated, count = crate_install_pattern.subn(
        rf"\g<1>{version}\2", path.read_text(), count=1
    )
    if count != 1:
        raise SystemExit(f"error: {path} has no pinned crates.io install command")
    return updated

updated_integration = update_crate_install(integration_path)

manifest_path.write_text(updated_manifest)
lock_path.write_text(updated_lock)
changelog_path.write_text(updated_changelog)
integration_path.write_text(updated_integration)
PY

cargo metadata --manifest-path "$project_dir/Cargo.toml" --locked --no-deps --format-version 1 >/dev/null
printf 'Prepared Code Buster %s.\n' "$version"
printf '%s\n' 'Review CHANGELOG.md, then run the verification commands in CONTRIBUTING.md.'
printf '%s\n' 'No tag, push, or release was created.'
