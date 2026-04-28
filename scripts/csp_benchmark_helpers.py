#!/usr/bin/env python3
"""Helpers for scripts/run_csp_benchmarks.sh.

Subcommands:
  parse-runs <bench_dir> <circuit>  Aggregate per-run measurements for one
                                    circuit and emit a single CSV row to stdout.
  human-to-bytes <value>            Convert a human-formatted byte string from
                                    the prover trace ("1.23 GB", "456 MB", etc.)
                                    to an integer byte count. Used by tests.

Bench layout produced by run_csp_benchmarks.sh::

    <bench_dir>/per_circuit/<circuit>/
        prove_<i>.time          # `/usr/bin/time -f '%e %M'` output
        prove_<i>.stderr        # provekit-cli prove stderr (span_stats trace)
        verify_<i>.time
        verify_<i>.stderr
        meta.txt                # key=value: pkp_size, proof_size

The "peak heap" comes from the largest "peak memory: <SI>B" entry emitted by
``tooling/cli/src/span_stats.rs`` over the prove invocation's trace. We strip
ANSI escapes and walk every span-close line; the outermost span propagates
its children's peak via ``data.peak_memory = max(...)`` so any of them is a
sufficient upper bound, but we keep the max for safety.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from statistics import mean

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# Suffix table from provekit_common::utils::human (BN254 utils). The middle
# entry is a regular ASCII space (no SI prefix). Order matters: we use it to
# look up the multiplier from a captured suffix character.
SI_SUFFIXES = "qryzafpnμm kMGTPEZYRQ"
SI_BASE_INDEX = SI_SUFFIXES.index(" ")  # power 0 lives at index 10
# The separator between number and SI suffix is U+202F NARROW NO-BREAK SPACE
# unless `{:#}` (alternate) is used. We accept either form.
NARROW_NBSP = " "
PEAK_MEMORY_RE = re.compile(
    rf"([0-9]+(?:\.[0-9]+)?)[{NARROW_NBSP} ]?([qryzafpnμmkMGTPEZYRQ])?B"
    r"\s+peak\s+memory",
)


def human_to_bytes(value: str) -> int:
    """Convert a "1.23 GB"-style string from the trace to an integer byte count.

    Accepts either a regular ASCII space or U+202F as the separator. Suffixes
    follow ``provekit_common::utils::human`` (q…Q). A literal "B" with no SI
    prefix returns the integer/float value rounded down.
    """
    cleaned = ANSI_RE.sub("", value).strip()
    if not cleaned.endswith("B"):
        raise ValueError(f"not a byte-formatted value: {value!r}")
    cleaned = cleaned[:-1].rstrip()  # drop trailing 'B'
    if cleaned and cleaned[-1] in SI_SUFFIXES and cleaned[-1] != " ":
        suffix = cleaned[-1]
        number_part = cleaned[:-1].rstrip()
    else:
        suffix = " "
        number_part = cleaned
    number_part = number_part.replace(NARROW_NBSP, "").strip()
    multiplier = 10 ** ((SI_SUFFIXES.index(suffix) - SI_BASE_INDEX) * 3)
    return int(float(number_part) * multiplier)


def parse_peak_heap_bytes(stderr_path: Path) -> int:
    """Return the largest "peak memory" value (bytes) found in the trace."""
    if not stderr_path.is_file():
        return 0
    text = ANSI_RE.sub("", stderr_path.read_text(encoding="utf-8", errors="replace"))
    peak = 0
    for match in PEAK_MEMORY_RE.finditer(text):
        number = float(match.group(1))
        suffix = match.group(2) or " "
        bytes_value = int(number * 10 ** ((SI_SUFFIXES.index(suffix) - SI_BASE_INDEX) * 3))
        peak = max(peak, bytes_value)
    return peak


def parse_time_file(time_path: Path) -> tuple[float, int]:
    """Read `/usr/bin/time -f '%e %M'` output: (wall_seconds, max_rss_kb).

    Returns (0.0, 0) if the file is missing or unparseable.
    """
    if not time_path.is_file():
        return 0.0, 0
    raw = time_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
    if not raw:
        return 0.0, 0
    parts = raw[-1].split()
    if len(parts) < 2:
        return 0.0, 0
    try:
        return float(parts[0]), int(parts[1])
    except ValueError:
        return 0.0, 0


def read_meta(meta_path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not meta_path.is_file():
        return out
    for line in meta_path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            out[key.strip()] = val.strip()
    return out


def parse_runs(bench_dir: Path, circuit: str) -> str:
    circuit_dir = bench_dir / "per_circuit" / circuit
    meta = read_meta(circuit_dir / "meta.txt")

    prove_runs: list[tuple[float, int, int]] = []
    verify_runs: list[tuple[float, int]] = []

    i = 1
    while True:
        time_path = circuit_dir / f"prove_{i}.time"
        if not time_path.is_file():
            break
        wall, rss_kb = parse_time_file(time_path)
        heap_bytes = parse_peak_heap_bytes(circuit_dir / f"prove_{i}.stderr")
        prove_runs.append((wall, rss_kb, heap_bytes))
        i += 1

    j = 1
    while True:
        time_path = circuit_dir / f"verify_{j}.time"
        if not time_path.is_file():
            break
        wall, _rss = parse_time_file(time_path)
        verify_runs.append((wall, _rss))
        j += 1

    if not prove_runs:
        return ""

    prove_time_ms = mean(r[0] for r in prove_runs) * 1000.0
    prover_rss_kb = mean(r[1] for r in prove_runs)
    prover_heap_bytes = mean(r[2] for r in prove_runs)
    verifier_time_ms = mean(r[0] for r in verify_runs) * 1000.0 if verify_runs else 0.0

    pkp_size = meta.get("pkp_size_bytes", "0")
    proof_size = meta.get("proof_size_bytes", "0")

    return ",".join(
        [
            circuit,
            f"{prove_time_ms:.1f}",
            f"{prover_rss_kb:.0f}",
            f"{prover_heap_bytes:.0f}",
            f"{verifier_time_ms:.1f}",
            proof_size,
            pkp_size,
            str(len(prove_runs)),
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("parse-runs")
    p.add_argument("bench_dir", type=Path)
    p.add_argument("circuit")

    p = sub.add_parser("human-to-bytes")
    p.add_argument("value")

    args = parser.parse_args()

    if args.cmd == "parse-runs":
        row = parse_runs(args.bench_dir, args.circuit)
        if row:
            print(row)
    elif args.cmd == "human-to-bytes":
        print(human_to_bytes(args.value))

    return 0


if __name__ == "__main__":
    sys.exit(main())
