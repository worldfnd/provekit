#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <markdown-file>" >&2
  exit 2
fi

markdown_file="$1"

python - "$markdown_file" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

replacements = {
    "Mean (ms)": "Mean",
    "Median (ms)": "Median",
    "P95 (ms)": "P95",
    "Min (ms)": "Min",
    "Max (ms)": "Max",
    "CPU total (ms)": "CPU total",
    "Avg ms": "Avg",
}

for old, new in replacements.items():
    text = text.replace(old, new)

path.write_text(text)
PY
