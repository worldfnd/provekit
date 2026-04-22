#!/usr/bin/env python3
"""Build a sticky PR comment for noir execution_success workflow runs."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

MARKER = "<!-- noir-execution-success-report -->"
MAX_COMMENT_CHARS = 62000
MIN_SECTION_CHARS = 1500


def read_report(path: Path, display_name: str) -> str:
    if not path.is_file():
        return f"(missing: {display_name})"

    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return f"(empty: {display_name})"
    return text


def parse_grouped_counts(grouped_report_text: str) -> dict[str, str]:
    counts: dict[str, str] = {}
    for key in ("PASS", "FAIL", "SKIP"):
        match = re.search(rf"^{key}=(\d+)$", grouped_report_text, flags=re.MULTILINE)
        counts[key] = match.group(1) if match else "n/a"
    return counts


def status_with_icon(status: str) -> str:
    normalized = (status or "unknown").strip().lower()
    labels = {
        "success": "[PASS]",
        "failure": "[FAIL]",
        "cancelled": "[CANCELLED]",
        "skipped": "[SKIPPED]",
    }
    return f"{labels.get(normalized, '[INFO]')} {normalized}"


def sanitize_code_fence(text: str) -> str:
    return text.replace("```", "``\\`")


def compose_comment(
    grouped_report_text: str,
    witness_report_text: str,
    grouped_truncated: bool,
    witness_truncated: bool,
    run_id: str,
    run_url: str,
    sha: str,
    noir_ref: str,
    status: str,
) -> str:
    counts = parse_grouped_counts(grouped_report_text)
    short_sha = sha[:12] if sha else "unknown"

    grouped_truncated_note = (
        "\n_Grouped report truncated to fit GitHub comment size limits._\n"
        if grouped_truncated
        else ""
    )
    witness_truncated_note = (
        "\n_ProveKit witness report truncated to fit GitHub comment size limits._\n"
        if witness_truncated
        else ""
    )

    lines = [
        MARKER,
        "## Noir execution_success report",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Workflow status | {status_with_icon(status)} |",
        f"| Noir ref | `{noir_ref}` |",
        f"| Commit | `{short_sha}` |",
        f"| Run | [#{run_id}]({run_url}) |",
        f"| PASS | {counts['PASS']} |",
        f"| FAIL | {counts['FAIL']} |",
        f"| SKIP | {counts['SKIP']} |",
        "",
        "<details>",
        "<summary><code>grouped_error_report.txt</code></summary>",
        "",
        "```text",
        sanitize_code_fence(grouped_report_text),
        "```",
        grouped_truncated_note,
        "</details>",
        "",
        "<details>",
        "<summary><code>provekit_witness_report.md</code></summary>",
        "",
        witness_report_text,
        witness_truncated_note,
        "</details>",
        "",
        "_This comment is automatically updated by the Noir Execution Success workflow._",
        "",
    ]

    return "\n".join(lines)


def clip_tail(text: str, min_chars: int, excess: int, label: str) -> tuple[str, bool]:
    if len(text) <= min_chars or excess <= 0:
        return text, False

    reduction = min(len(text) - min_chars, excess + 1024)
    kept = text[: len(text) - reduction].rstrip()
    omitted = len(text) - len(kept)
    clipped = f"{kept}\n\n[... truncated {omitted} characters from {label} ...]"
    return clipped, True


def build_with_truncation(
    grouped_report_text: str,
    witness_report_text: str,
    run_id: str,
    run_url: str,
    sha: str,
    noir_ref: str,
    status: str,
) -> str:
    grouped_work = grouped_report_text
    witness_work = witness_report_text
    grouped_truncated = False
    witness_truncated = False

    for _ in range(128):
        comment = compose_comment(
            grouped_work,
            witness_work,
            grouped_truncated=grouped_truncated,
            witness_truncated=witness_truncated,
            run_id=run_id,
            run_url=run_url,
            sha=sha,
            noir_ref=noir_ref,
            status=status,
        )
        if len(comment) <= MAX_COMMENT_CHARS:
            return comment

        excess = len(comment) - MAX_COMMENT_CHARS
        witness_work, witness_changed = clip_tail(
            witness_work, MIN_SECTION_CHARS, excess, "provekit_witness_report.md"
        )
        witness_truncated = witness_truncated or witness_changed
        if witness_changed:
            continue

        grouped_work, grouped_changed = clip_tail(
            grouped_work, MIN_SECTION_CHARS, excess, "grouped_error_report.txt"
        )
        grouped_truncated = grouped_truncated or grouped_changed
        if grouped_changed:
            continue

        break

    # Final hard guard if both reports are already near minimum length.
    fallback = compose_comment(
        grouped_work,
        witness_work,
        grouped_truncated=True,
        witness_truncated=True,
        run_id=run_id,
        run_url=run_url,
        sha=sha,
        noir_ref=noir_ref,
        status=status,
    )
    if len(fallback) <= MAX_COMMENT_CHARS:
        return fallback

    hard_cut = fallback[: MAX_COMMENT_CHARS - 120].rstrip()
    return f"{hard_cut}\n\n_Comment truncated due to GitHub size limits._\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grouped-report", required=True, type=Path)
    parser.add_argument("--witness-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--noir-ref", required=True)
    parser.add_argument("--status", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    grouped_report_text = read_report(args.grouped_report, "grouped_error_report.txt")
    witness_report_text = read_report(args.witness_report, "provekit_witness_report.md")

    body = build_with_truncation(
        grouped_report_text=grouped_report_text,
        witness_report_text=witness_report_text,
        run_id=args.run_id,
        run_url=args.run_url,
        sha=args.sha,
        noir_ref=args.noir_ref,
        status=args.status,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(body, encoding="utf-8")
    print(f"Wrote PR comment body to {args.output} ({len(body)} chars)")


if __name__ == "__main__":
    main()
