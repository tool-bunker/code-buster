#!/usr/bin/env python3
"""Keep the command contract fixture synchronized with the authoritative enum."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "test/fixtures/current_contract_inventory.json"

inventory = json.loads(OUTPUT.read_text())
source = (ROOT / "lib/src/cli/cli_contract.dart").read_text()
block_match = re.search(r"enum CodeBusterCommand \{(.*?)\n\}", source, re.S)
if block_match is None:
    raise SystemExit("Unable to locate CodeBusterCommand")
inventory["dart"]["commands"] = sorted(
    re.findall(r"^\s{2}([a-z][a-zA-Z]+)[,;]?$", block_match.group(1), re.M)
)
inventory["generated_from"] = ["lib/src"]
OUTPUT.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
print(OUTPUT.relative_to(ROOT))
