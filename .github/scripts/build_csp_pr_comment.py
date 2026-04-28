#!/usr/bin/env python3
"""Build a sticky PR comment for the CSP benchmarks workflow.

Reads the CSV emitted by ``scripts/run_csp_benchmarks.sh`` (one row per
circuit) and renders it as a markdown table with human-readable units.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

MARKER = "<!-- csp-benchmarks-report -->"
MAX_COMMENT_CHARS = 62000


def fmt_bytes(value: float) -> str:
    if value <= 0:
        return "—"
    units = ("B", "KB", "MB", "GB", "TB")
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if value >= 100 or idx == 0:
        return f"{value:.0f} {units[idx]}"
    return f"{value:.2f} {units[idx]}"


def fmt_kb_to_bytes(rss_kb: float) -> str:
    return fmt_bytes(rss_kb * 1024.0)


def fmt_ms(ms: float) -> str:
    if ms <= 0:
        return "—"
    if ms < 1000:
        return f"{ms:.0f} ms"
    return f"{ms / 1000.0:.2f} s"


def status_with_icon(status: str) -> str:
    normalized = (status or "unknown").strip().lower()
    labels = {
        "success": "[PASS]",
        "failure": "[FAIL]",
        "cancelled": "[CANCELLED]",
        "skipped": "[SKIPPED]",
    }
    return f"{labels.get(normalized, '[INFO]')} {normalized}"


def read_rows(csv_path: Path) -> list[dict[str, str]]:
    if not csv_path.is_file():
        return []
    with csv_path.open(newline="") as f:
        return list(csv.DictReader(f))


def render_table(rows: list[dict[str, str]]) -> str:
    if not rows:
        return "_No benchmark results were produced._"

    header = (
        "| Circuit | Prover time | Peak RSS | Peak heap | Verifier time | "
        "Proof size | PKP size | Runs |"
    )
    sep = "|---|---:|---:|---:|---:|---:|---:|---:|"
    lines = [header, sep]
    for row in sorted(rows, key=lambda r: r.get("circuit", "")):
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{row['circuit']}`",
                    fmt_ms(float(row.get("prover_time_ms", 0) or 0)),
                    fmt_kb_to_bytes(float(row.get("prover_peak_rss_kb", 0) or 0)),
                    fmt_bytes(float(row.get("prover_heap_peak_bytes", 0) or 0)),
                    fmt_ms(float(row.get("verifier_time_ms", 0) or 0)),
                    fmt_bytes(float(row.get("proof_size_bytes", 0) or 0)),
                    fmt_bytes(float(row.get("pkp_size_bytes", 0) or 0)),
                    row.get("runs", "—"),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def compose_comment(
    rows: list[dict[str, str]],
    run_id: str,
    run_url: str,
    sha: str,
    status: str,
    runs_per_circuit: str,
) -> str:
    short_sha = sha[:12] if sha else "unknown"
    table = render_table(rows)
    lines = [
        MARKER,
        "## CSP benchmarks",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Workflow status | {status_with_icon(status)} |",
        f"| Commit | `{short_sha}` |",
        f"| Run | [#{run_id}]({run_url}) |",
        f"| Circuits benchmarked | {len(rows)} |",
        f"| Iterations averaged per circuit | {runs_per_circuit} |",
        "",
        "Prover time, peak RSS, peak heap, and verifier time are arithmetic means "
        "across the iterations. Peak heap comes from the largest "
        "`peak memory` entry in `provekit-cli prove`'s tracing output; peak RSS "
        "is reported by `/usr/bin/time -v` (max-resident-set-size).",
        "",
        "<details open>",
        "<summary>Results</summary>",
        "",
        table,
        "",
        "</details>",
        "",
        "_This comment is automatically updated by the CSP Benchmarks workflow._",
        "",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-csv", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--runs-per-circuit", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = read_rows(args.results_csv)
    body = compose_comment(
        rows=rows,
        run_id=args.run_id,
        run_url=args.run_url,
        sha=args.sha,
        status=args.status,
        runs_per_circuit=args.runs_per_circuit,
    )
    if len(body) > MAX_COMMENT_CHARS:
        cut = body[: MAX_COMMENT_CHARS - 80].rstrip()
        body = f"{cut}\n\n_Comment truncated due to GitHub size limits._\n"

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(body, encoding="utf-8")
    print(f"Wrote PR comment body to {args.output} ({len(body)} chars)")


if __name__ == "__main__":
    main()
