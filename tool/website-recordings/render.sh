#!/bin/sh
set -eu

recordings_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$recordings_dir/../.." && pwd)
website_dir="$repository_root/website"

npx --yes terminalizer render \
  "$recordings_dir/repository-overview" \
  -o "$website_dir/assets/repository-overview.gif"

npx --yes terminalizer render \
  "$recordings_dir/quality-workflow" \
  -o "$website_dir/assets/quality-workflow.gif"
