#!/usr/bin/env python3
"""Generate a ProveKit-only witness count report.

Usage: python3 generate_provekit_witness_report.py <witness_csv> <output_dir>

Reads a CSV of post-GE constraint and witness counts produced by
scripts/run_noir_execution_success.sh and writes provekit_witness_report.md
to <output_dir>.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

SKIP_LIST = Path(__file__).resolve().parent / "noir_skip_tests.txt"


def load_skip_tests() -> set[str]:
    if not SKIP_LIST.is_file():
        return set()
    skip: set[str] = set()
    for raw in SKIP_LIST.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        skip.add(line)
    return skip


def main(csv_path: Path, out_dir: Path) -> None:
    skip_tests = load_skip_tests()

    rows: dict[str, tuple[int | None, int | None]] = {}
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            leaf = row["test_name"].split("/")[-1]
            if leaf in skip_tests:
                continue

            def _parse(key: str) -> int | None:
                val = row.get(key, "")
                try:
                    return int(val)
                except (TypeError, ValueError):
                    return None

            rows[leaf] = (_parse("provekit_constraints"), _parse("provekit_witnesses"))

    lines = [
        "# ProveKit Witness Counts",
        "",
        f"Captured post-GE constraint and witness counts for {len(rows)} circuits.",
        "",
        "| Test | Constraints (post-GE) | Witnesses (post-GE) |",
        "|------|------------------------|----------------------|",
    ]
    for name in sorted(rows):
        constraints, witnesses = rows[name]
        c = "-" if constraints is None else str(constraints)
        w = "-" if witnesses is None else str(witnesses)
        lines.append(f"| {name} | {c} | {w} |")

    out_path = out_dir / "provekit_witness_report.md"
    out_path.write_text("\n".join(lines) + "\n")
    print(f"Wrote {out_path} ({len(rows)} circuits)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <witness_csv> <output_dir>", file=sys.stderr)
        sys.exit(1)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
