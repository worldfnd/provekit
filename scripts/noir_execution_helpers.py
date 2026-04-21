#!/usr/bin/env python3
"""Helpers for scripts/run_noir_execution_success.sh.

Subcommands:
  discover <test_root>                      — list runnable test dirs
  resolve-prover-toml <project_dir> <name>  — find Prover.toml for a package
  package-name <project_dir>                — read [package].name from Nargo.toml
  build-report <log_dir> <passed_count>     — write grouped_error_report.txt
  skip-tests                                — print the skip list (one per line)

The skip list lives in scripts/noir_skip_tests.txt and is the single source
of truth shared with scripts/generate_witness_comparison.py.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

SKIP_LIST_FILE = Path(__file__).with_name("noir_skip_tests.txt")


def load_skip_tests() -> set[str]:
    """Return the skip list parsed from noir_skip_tests.txt.

    Blank lines and lines starting with `#` are ignored. Inline `#` comments
    are stripped. Returns an empty set if the file is missing.
    """
    if not SKIP_LIST_FILE.is_file():
        return set()
    names: set[str] = set()
    for raw in SKIP_LIST_FILE.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            names.add(line)
    return names


def discover_tests(root: Path) -> list[str]:
    """Return candidate test project paths relative to ``root``.

    Mirrors the legacy shell heredoc: a path is a candidate if it is a
    workspace default-member, or if it has both a `[package]` entry in its
    Nargo.toml and a sibling Prover.toml. Nested projects under a workspace
    default-member are suppressed.
    """
    nargo_data: dict[str, dict] = {}
    for nargo in root.rglob("Nargo.toml"):
        rel = nargo.parent.relative_to(root).as_posix()
        try:
            data = tomllib.loads(nargo.read_text())
        except Exception:
            data = {}
        nargo_data[rel] = data

    workspace_default_roots: set[str] = set()
    for rel, data in nargo_data.items():
        ws = data.get("workspace")
        if isinstance(ws, dict) and "default-member" in ws:
            workspace_default_roots.add(rel)

    suppressed: set[str] = set()
    for ws_rel in workspace_default_roots:
        ws_path = Path(ws_rel) if ws_rel != "." else Path()
        for rel in nargo_data:
            rel_path = Path(rel) if rel != "." else Path()
            if rel_path != ws_path and ws_path in rel_path.parents:
                suppressed.add(rel)

    candidates: set[str] = set(workspace_default_roots)
    for rel, data in nargo_data.items():
        if rel in suppressed:
            continue
        pkg = data.get("package")
        if isinstance(pkg, dict) and "name" in pkg:
            if (root / rel / "Prover.toml").is_file():
                candidates.add(rel)

    return sorted(candidates)


def resolve_prover_toml(project_dir: Path, package_name: str) -> str:
    """Return Prover.toml path (relative to ``project_dir``) for ``package_name``.

    Prefers a Prover.toml located next to the Nargo.toml whose package name
    matches. Falls back to a root-level Prover.toml, then to the sole
    Prover.toml under the project when unambiguous. Returns "" otherwise.
    """
    matches: list[str] = []
    for nargo in sorted(project_dir.rglob("Nargo.toml")):
        try:
            data = tomllib.loads(nargo.read_text())
        except Exception:
            continue
        pkg = data.get("package")
        if not isinstance(pkg, dict) or pkg.get("name") != package_name:
            continue
        prover = nargo.parent / "Prover.toml"
        if prover.is_file():
            matches.append(prover.relative_to(project_dir).as_posix())

    if matches:
        matches.sort(key=lambda p: (p.count("/"), p))
        return matches[0]

    root_prover = project_dir / "Prover.toml"
    if root_prover.is_file():
        return "Prover.toml"

    all_provers = sorted(project_dir.rglob("Prover.toml"))
    if len(all_provers) == 1:
        return all_provers[0].relative_to(project_dir).as_posix()

    return ""


def read_package_name(project_dir: Path) -> str:
    """Return [package].name from ``project_dir/Nargo.toml`` or ""."""
    nargo = project_dir / "Nargo.toml"
    if not nargo.is_file():
        return ""
    try:
        data = tomllib.loads(nargo.read_text())
    except Exception:
        return ""
    pkg = data.get("package")
    if isinstance(pkg, dict):
        return str(pkg.get("name", ""))
    return ""


_BLACKBOX_RE = re.compile(
    r"not implemented: Other black box function: BLACKBOX::([A-Z0-9_]+)"
)
_PANIC_RE = re.compile(r"panicked at [^\n]*:\n([^\n]+)")
_SOLVE_RE = re.compile(r"Failed to solve program: '([^']+)'")
_COMPILE_ERR_RE = re.compile(r"^error:\s*([^\n]+)", flags=re.M)
_COMPILE_BUG_RE = re.compile(r"^bug:\s*([^\n]+)", flags=re.M)
_GENERIC_ERR_RE = re.compile(r"^Error:\s*([^\n]+)", flags=re.M)
_FAIL_STAGE_RE = re.compile(r"FAIL: ([^\n]+)")
_SKIP_REASON_RE = re.compile(r"SKIP: ([^\n]+)")


def _classify_failure(text: str, stage: str) -> str:
    blackbox = _BLACKBOX_RE.search(text)
    if blackbox:
        return f"Not implemented blackbox: {blackbox.group(1)} ({stage})"
    if "Program must have one entry point." in text:
        return f"Program must have one entry point ({stage})"
    panic = _PANIC_RE.search(text)
    if panic:
        return f"Panic: {panic.group(1).strip()} ({stage})"
    solve = _SOLVE_RE.search(text)
    if solve:
        return f"Failed to solve program: {solve.group(1)} ({stage})"
    if "Failed assertion" in text:
        return f"Failed assertion ({stage})"
    compile_error = _COMPILE_ERR_RE.search(text)
    if compile_error:
        return f"Compile error: {compile_error.group(1).strip()} ({stage})"
    compile_bug = _COMPILE_BUG_RE.search(text)
    if compile_bug:
        return f"Compile bug: {compile_bug.group(1).strip()} ({stage})"
    generic = _GENERIC_ERR_RE.search(text)
    if generic:
        return f"Error: {generic.group(1).strip()} ({stage})"
    return f"Unknown failure ({stage})"


def build_grouped_report(log_dir: Path, passed_count: int) -> None:
    """Scan ``log_dir/per_test/*.log`` and write ``log_dir/grouped_error_report.txt``.

    PASS logs are deleted by the shell runner after each successful test, so
    the PASS count is threaded in as ``passed_count`` rather than inferred.
    """
    per_test_dir = log_dir / "per_test"
    report_file = log_dir / "grouped_error_report.txt"

    logs = sorted(per_test_dir.glob("*.log"))
    status_counts = {"PASS": passed_count, "FAIL": 0, "SKIP": 0}
    grouped: dict[str, list[str]] = defaultdict(list)
    stage_groups: dict[str, list[str]] = defaultdict(list)

    for fp in logs:
        text = fp.read_text(errors="replace")
        name = fp.stem

        if "SKIP:" in text:
            status_counts["SKIP"] += 1
            skip_match = _SKIP_REASON_RE.search(text)
            reason = skip_match.group(1).strip() if skip_match else "unknown"
            grouped[f"SKIP: {reason}"].append(name)
            continue

        status_counts["FAIL"] += 1
        fail_stages = _FAIL_STAGE_RE.findall(text)
        stage = fail_stages[-1].strip() if fail_stages else "unknown stage"
        stage_groups[stage].append(name)
        grouped[_classify_failure(text, stage)].append(name)

    with report_file.open("w") as f:
        f.write(f"logs={len(logs)}\n")
        f.write(f"PASS={status_counts['PASS']}\n")
        f.write(f"FAIL={status_counts['FAIL']}\n")
        f.write(f"SKIP={status_counts['SKIP']}\n")
        f.write("\n[stages]\n")
        for stage, tests in sorted(stage_groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            f.write(f"{stage}\t{len(tests)}\t{', '.join(tests)}\n")
        f.write("\n[grouped]\n")
        for key, tests in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            f.write(f"{len(tests)}\t{key}\t{', '.join(tests)}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("discover", help="list runnable test dirs under <test_root>")
    p.add_argument("test_root", type=Path)

    p = sub.add_parser("resolve-prover-toml")
    p.add_argument("project_dir", type=Path)
    p.add_argument("package_name")

    p = sub.add_parser("package-name")
    p.add_argument("project_dir", type=Path)

    p = sub.add_parser("build-report")
    p.add_argument("log_dir", type=Path)
    p.add_argument("passed_count", type=int)

    sub.add_parser("skip-tests", help="print the skip list, one name per line")

    args = parser.parse_args()

    if args.cmd == "discover":
        for name in discover_tests(args.test_root):
            print(name)
    elif args.cmd == "resolve-prover-toml":
        print(resolve_prover_toml(args.project_dir, args.package_name))
    elif args.cmd == "package-name":
        print(read_package_name(args.project_dir))
    elif args.cmd == "build-report":
        build_grouped_report(args.log_dir, args.passed_count)
    elif args.cmd == "skip-tests":
        for name in sorted(load_skip_tests()):
            print(name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
