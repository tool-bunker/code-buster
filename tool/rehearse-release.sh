#!/bin/sh
# Build and exercise a host release artifact from the committed source tree.
set -eu

usage() {
  printf '%s\n' 'usage: ./tool/rehearse-release.sh [output-directory]' >&2
}

if [ "$#" -gt 1 ]; then
  usage
  exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_dir=${1:-"$project_dir/dist/rehearsal"}

for command in cargo git tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'error: %s is required\n' "$command" >&2
    exit 1
  fi
done

system=$(uname -s)
machine=$(uname -m)
case "$system:$machine" in
  Darwin:arm64|Darwin:aarch64)
    platform=macos-arm64
    ;;
  Darwin:x86_64|Darwin:amd64)
    platform=macos-x64
    ;;
  Linux:x86_64|Linux:amd64)
    platform=linux-x64
    ;;
  Linux:arm64|Linux:aarch64)
    platform=linux-arm64
    ;;
  *)
    printf 'error: unsupported rehearsal host: %s %s\n' "$system" "$machine" >&2
    exit 1
    ;;
esac

revision=$(git -C "$project_dir" rev-parse --verify HEAD)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/code-buster-release.XXXXXX")
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM

source_dir="$work_dir/source"
build_dir="$work_dir/build"
stage_dir="$work_dir/stage"
install_dir="$work_dir/install"
mkdir -p "$source_dir" "$build_dir" "$stage_dir" "$install_dir" "$output_dir"

git -C "$project_dir" archive "$revision" | tar -x -C "$source_dir"
package_id=$(cargo pkgid --manifest-path "$source_dir/Cargo.toml")
version=${package_id##*@}

printf 'Building code-buster %s from %s for %s...\n' "$version" "$revision" "$platform"
CARGO_TARGET_DIR="$build_dir" cargo build \
  --manifest-path "$source_dir/Cargo.toml" \
  --release \
  --locked

cp "$build_dir/release/cb" "$stage_dir/cb"
cp "$source_dir/LICENSE" "$stage_dir/LICENSE"
cp "$source_dir/README.md" "$stage_dir/README.md"
archive_name="code-buster-$platform.tar.gz"
archive_path="$output_dir/$archive_name"
rm -f "$archive_path" "$output_dir/SHA256SUMS"
tar -C "$stage_dir" -czf "$archive_path" cb LICENSE README.md

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_dir" && sha256sum "$archive_name" > SHA256SUMS)
  (cd "$output_dir" && sha256sum -c SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$output_dir" && shasum -a 256 "$archive_name" > SHA256SUMS)
  (cd "$output_dir" && shasum -a 256 -c SHA256SUMS)
else
  printf '%s\n' 'error: sha256sum or shasum is required' >&2
  exit 1
fi

tar -xzf "$archive_path" -C "$install_dir"
"$install_dir/cb" version
"$install_dir/cb" completions bash > "$work_dir/completions.bash"
"$install_dir/cb" config \
  --files \
  --root "$source_dir/tests/fixtures/preview" \
  --format json > "$work_dir/files.json"
"$install_dir/cb" summary \
  --root "$source_dir/tests/fixtures/preview" \
  --format json \
  --advisory \
  --allow-empty > "$work_dir/summary.json"

printf 'Release rehearsal passed.\n'
printf 'Artifact: %s\n' "$archive_path"
printf 'Checksums: %s\n' "$output_dir/SHA256SUMS"
printf '%s\n' 'No tag, push, or release was created.'
