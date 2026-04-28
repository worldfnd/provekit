#!/usr/bin/env python3
"""Build a sticky PR comment for the CSP benchmarks workflow.

Reads the CSV emitted by ``scripts/run_csp_benchmarks.sh`` (one row per
circuit) and renders it as a markdown table with human-readable units. If
``--baseline-csv`` is given, each metric cell appends a percentage delta
versus the baseline value (last successful CSP-benchmarks run on main).
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

MARKER = "<!-- csp-benchmarks-report -->"
MAX_COMMENT_CHARS = 62000

# Metric columns we render with a delta. Order matches the table header.
METRIC_COLUMNS: tuple[tuple[str, str], ...] = (
    ("prover_time_ms", "ms"),
    ("prover_peak_rss_kb", "kb"),
    ("prover_heap_peak_bytes", "bytes"),
    ("verifier_time_ms", "ms"),
    ("proof_size_bytes", "bytes"),
    ("pkp_size_bytes", "bytes"),
)


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


def fmt_value(unit: str, value: float) -> str:
    if unit == "ms":
        return fmt_ms(value)
    if unit == "kb":
        return fmt_kb_to_bytes(value)
    return fmt_bytes(value)


def fmt_delta(current: float, baseline: float | None) -> str:
    """Return a compact delta-vs-baseline annotation, or empty string.

    - Returns "" when no baseline is available.
    - Returns "(new)" when current is present but baseline is missing
      for this circuit.
    - Returns "(±0.0%)" / "(+1.2%)" / "(-3.4%)" otherwise.
    """
    if baseline is None:
        return ""
    if baseline <= 0:
        # Baseline collected zero (e.g., older CSV without this metric).
        # Don't show a misleading divide-by-zero ratio.
        return ""
    if current <= 0:
        return ""
    delta_pct = (current - baseline) / baseline * 100.0
    if abs(delta_pct) < 0.05:
        return " (±0.0%)"
    sign = "+" if delta_pct > 0 else ""
    return f" ({sign}{delta_pct:.1f}%)"


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


def index_baseline(rows: list[dict[str, str]]) -> dict[str, dict[str, float]]:
    """Index baseline rows by circuit name with float metric values."""
    out: dict[str, dict[str, float]] = {}
    for row in rows:
        circuit = (row.get("circuit") or "").strip()
        if not circuit:
            continue
        metrics: dict[str, float] = {}
        for metric, _unit in METRIC_COLUMNS:
            try:
                metrics[metric] = float(row.get(metric) or 0)
            except ValueError:
                metrics[metric] = 0.0
        out[circuit] = metrics
    return out


def render_table(
    rows: list[dict[str, str]],
    baseline: dict[str, dict[str, float]],
    has_baseline_file: bool,
) -> str:
    if not rows:
        return "_No benchmark results were produced._"

    header = (
        "| Circuit | Prover time | Peak RSS | Peak heap | Verifier time | "
        "Proof size | PKP size |"
    )
    sep = "|---|---:|---:|---:|---:|---:|---:|"
    lines = [header, sep]

    for row in sorted(rows, key=lambda r: r.get("circuit", "")):
        circuit = row.get("circuit", "")
        baseline_metrics = baseline.get(circuit)

        cells = [f"`{circuit}`"]
        for metric, unit in METRIC_COLUMNS:
            try:
                value = float(row.get(metric) or 0)
            except ValueError:
                value = 0.0

            value_str = fmt_value(unit, value)

            if has_baseline_file and value_str != "—":
                if baseline_metrics is None:
                    delta = " (new)"
                else:
                    delta = fmt_delta(value, baseline_metrics.get(metric))
                cells.append(f"{value_str}{delta}")
            else:
                cells.append(value_str)
        lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines)


def compose_comment(
    rows: list[dict[str, str]],
    baseline: dict[str, dict[str, float]],
    baseline_run_id: str,
    has_baseline_file: bool,
    run_id: str,
    run_url: str,
    sha: str,
    status: str,
    runs_per_circuit: str,
) -> str:
    short_sha = sha[:12] if sha else "unknown"
    table = render_table(rows, baseline, has_baseline_file)

    if has_baseline_file:
        if baseline_run_id:
            baseline_note = (
                f"Each metric cell shows the current value followed by the "
                f"percentage delta against the latest successful "
                f"[`main` run #{baseline_run_id}](https://github.com/worldfnd/provekit/actions/runs/{baseline_run_id}). "
                f"`(new)` marks circuits absent from the baseline."
            )
        else:
            baseline_note = (
                "Each metric cell shows the current value followed by the "
                "percentage delta against the latest successful `main` run. "
                "`(new)` marks circuits absent from the baseline."
            )
    else:
        baseline_note = (
            "_No baseline available yet — deltas will appear once this "
            "workflow has produced at least one successful `main` run._"
        )

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
        baseline_note,
        "",
        "<details open>",
        "<summary>Results</summary>",
        "",
        table,
        "",
        "</details>",
        "",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-csv", required=True, type=Path)
    parser.add_argument(
        "--baseline-csv",
        type=Path,
        default=None,
        help="Optional CSV from the latest successful main run.",
    )
    parser.add_argument(
        "--baseline-run-id",
        default="",
        help="Optional Actions run id of the baseline (for the link in the comment).",
    )
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

    has_baseline_file = bool(
        args.baseline_csv and args.baseline_csv.is_file()
    )
    baseline_rows = read_rows(args.baseline_csv) if has_baseline_file else []
    baseline = index_baseline(baseline_rows)

    body = compose_comment(
        rows=rows,
        baseline=baseline,
        baseline_run_id=args.baseline_run_id,
        has_baseline_file=has_baseline_file,
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
