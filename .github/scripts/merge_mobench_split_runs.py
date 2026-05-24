#!/usr/bin/env python3
"""Merge one-sample mobench CI summaries into a normal per-device summary."""

from __future__ import annotations

import argparse
import copy
import csv
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any


def percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return ordered[index]


def int_median(values: list[int]) -> int:
    if not values:
        return 0
    return int(median(values))


def load_reports(samples_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    reports = []
    for summary_path in sorted(samples_dir.glob("sample-*/summary.json")):
        with summary_path.open() as file:
            reports.append((summary_path, json.load(file)))
    if not reports:
        raise SystemExit(f"no sample summary.json files found under {samples_dir}")
    return reports


def single_benchmark(report: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    benchmark_results = report.get("benchmark_results") or {}
    if len(benchmark_results) != 1:
        raise ValueError("expected exactly one device in benchmark_results")
    device, benchmarks = next(iter(benchmark_results.items()))
    if len(benchmarks) != 1:
        raise ValueError("expected exactly one benchmark in benchmark_results")
    return device, benchmarks[0]


def merge_resources(samples: list[dict[str, Any]], benches: list[dict[str, Any]]) -> dict[str, Any]:
    resources = copy.deepcopy(benches[0].get("resources") or {})
    cpu_samples = [sample.get("cpu_time_ms") for sample in samples if sample.get("cpu_time_ms") is not None]
    peak_memory = [
        sample.get("peak_memory_kb") for sample in samples if sample.get("peak_memory_kb") is not None
    ]
    process_peak = [
        sample.get("process_peak_memory_kb")
        for sample in samples
        if sample.get("process_peak_memory_kb") is not None
    ]

    if cpu_samples:
        resources["cpu_total_ms"] = int(sum(cpu_samples))
        resources["elapsed_cpu_ms"] = int(sum(cpu_samples))
        resources["cpu_median_ms"] = int_median([int(value) for value in cpu_samples])
    if peak_memory:
        resources["peak_memory_kb"] = int(max(peak_memory))
        resources["peak_memory_growth_kb"] = int(max(peak_memory))
    if process_peak:
        resources["process_peak_memory_kb"] = int(max(process_peak))

    resources.setdefault("platform", "android")
    resources.setdefault("memory_process", "isolated_worker")
    return resources


def merge_reports(
    reports: list[tuple[Path, dict[str, Any]]],
    function: str,
    iterations: int,
    warmup: int,
) -> dict[str, Any]:
    device_names = []
    benches = []
    for _, report in reports:
        device, benchmark = single_benchmark(report)
        device_names.append(device)
        benches.append(benchmark)

    if len(set(device_names)) != 1:
        raise ValueError(f"split samples reported multiple devices: {sorted(set(device_names))}")
    if any(benchmark.get("function") != function for benchmark in benches):
        functions = sorted({benchmark.get("function") for benchmark in benches})
        raise ValueError(f"split samples reported unexpected functions: {functions}")

    device = device_names[0]
    base = copy.deepcopy(reports[0][1])
    samples: list[dict[str, Any]] = []
    for benchmark in benches:
        samples.extend(copy.deepcopy(benchmark.get("samples") or []))

    if len(samples) != iterations:
        raise ValueError(f"expected {iterations} measured samples, got {len(samples)}")

    sample_ns = [int(sample["duration_ns"]) for sample in samples]
    mean_ns = int(sum(sample_ns) / len(sample_ns))
    median_ns = int_median(sample_ns)
    min_ns = min(sample_ns)
    max_ns = max(sample_ns)
    p95_ns = percentile(sample_ns, 95.0)
    resources = merge_resources(samples, benches)

    merged_benchmark = copy.deepcopy(benches[0])
    merged_benchmark.update(
        {
            "function": function,
            "samples": samples,
            "samples_ns": sample_ns,
            "min_ns": min_ns,
            "max_ns": max_ns,
            "mean_ns": mean_ns,
            "median_ns": median_ns,
            "p95_ns": p95_ns,
            "resources": resources,
            "phases": [{"name": "prove", "duration_ns": int(sum(sample_ns))}],
            "spec": {
                **(copy.deepcopy(merged_benchmark.get("spec") or {})),
                "name": function,
                "iterations": iterations,
                "warmup": warmup,
            },
            "stats": {
                "avg_ns": mean_ns,
                "mean_ns": mean_ns,
                "median_ns": median_ns,
                "min_ns": min_ns,
                "max_ns": max_ns,
            },
        }
    )

    summary_benchmark = {
        "function": function,
        "samples": len(samples),
        "mean_ns": mean_ns,
        "median_ns": median_ns,
        "p95_ns": p95_ns,
        "min_ns": min_ns,
        "max_ns": max_ns,
        "resource_usage": resources,
    }

    base["benchmark_results"] = {device: [merged_benchmark]}
    base["summary"] = {
        **(copy.deepcopy(base.get("summary") or {})),
        "target": "android",
        "device_summaries": [{"device": device, "benchmarks": [summary_benchmark]}],
    }
    base["spec"] = {
        **(copy.deepcopy(base.get("spec") or {})),
        "name": function,
        "iterations": iterations,
        "warmup": warmup,
    }
    base.setdefault("ci", {})["split_android_samples"] = True
    base["ci"]["split_sample_count"] = iterations
    return base


def human_duration(ns: int) -> str:
    seconds = ns / 1_000_000_000.0
    if seconds >= 1:
        return f"{seconds:.3f}s"
    return f"{seconds * 1000:.1f}ms"


def human_memory(kb: int | None) -> str:
    if not kb:
        return "-"
    mb = kb / 1024.0
    if mb >= 1024:
        return f"{mb / 1024.0:.2f} GB"
    return f"{mb:.2f} MB"


def write_csv(output_dir: Path, device: str, benchmark: dict[str, Any]) -> None:
    resources = benchmark.get("resource_usage") or benchmark.get("resources") or {}
    fieldnames = [
        "device",
        "function",
        "samples",
        "mean_ns",
        "median_ns",
        "p95_ns",
        "min_ns",
        "max_ns",
        "cpu_total_ms",
        "cpu_median_ms",
        "peak_memory_kb",
        "peak_memory_growth_kb",
        "process_peak_memory_kb",
    ]
    with (output_dir / "results.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(
            {
                "device": device,
                "function": benchmark["function"],
                "samples": benchmark["samples"],
                "mean_ns": benchmark["mean_ns"],
                "median_ns": benchmark["median_ns"],
                "p95_ns": benchmark["p95_ns"],
                "min_ns": benchmark["min_ns"],
                "max_ns": benchmark["max_ns"],
                "cpu_total_ms": resources.get("cpu_total_ms", ""),
                "cpu_median_ms": resources.get("cpu_median_ms", ""),
                "peak_memory_kb": resources.get("peak_memory_kb", ""),
                "peak_memory_growth_kb": resources.get("peak_memory_growth_kb", ""),
                "process_peak_memory_kb": resources.get("process_peak_memory_kb", ""),
            }
        )


def write_markdown(output_dir: Path, device_arg: str, device: str, benchmark: dict[str, Any], warmup: int) -> None:
    resources = benchmark.get("resource_usage") or benchmark.get("resources") or {}
    mean_ns = int(benchmark["mean_ns"])
    samples = int(benchmark["samples"])
    cpu_total = resources.get("cpu_total_ms")
    cpu_median = resources.get("cpu_median_ms")
    peak_growth = resources.get("peak_memory_growth_kb")
    process_peak = resources.get("process_peak_memory_kb")
    wall_total_ns = mean_ns * samples
    cpu_wall = "-"
    if cpu_total is not None and wall_total_ns:
        cpu_wall = f"{(cpu_total / (wall_total_ns / 1_000_000.0)) * 100:.1f}%"

    generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    lines = [
        "### Benchmark Summary",
        "",
        f"- Generated: {generated}",
        "- Target: Android",
        f"- Function: {benchmark['function']}",
        f"- Iterations/Warmup: {samples} / {warmup}",
        f"- Devices: {device_arg}",
        "",
        "| Device | Function | Samples | Warmup | Wall mean / iter | Wall total | CPU median / iter | CPU total | CPU / wall | Peak growth | Process peak |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {device} | {benchmark['function']} | {samples} | {warmup} | "
            f"{human_duration(mean_ns)} | {human_duration(wall_total_ns)} | "
            f"{human_duration(int(cpu_median) * 1_000_000) if cpu_median is not None else '-'} | "
            f"{human_duration(int(cpu_total) * 1_000_000) if cpu_total is not None else '-'} | "
            f"{cpu_wall} | {human_memory(peak_growth)} | {human_memory(process_peak)} |"
        ),
        "",
    ]
    (output_dir / "summary.md").write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--function", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    args = parser.parse_args()

    reports = load_reports(args.samples_dir)
    merged = merge_reports(reports, args.function, args.iterations, args.warmup)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    with (args.output_dir / "summary.json").open("w") as file:
        json.dump(merged, file, indent=2)
        file.write("\n")

    device, benchmark = single_benchmark(merged)
    summary_benchmark = merged["summary"]["device_summaries"][0]["benchmarks"][0]
    write_csv(args.output_dir, device, summary_benchmark)
    write_markdown(args.output_dir, args.device, device, summary_benchmark, args.warmup)

    print(f"Merged {args.iterations} split sample(s) for {args.function} on {args.device}")


if __name__ == "__main__":
    main()
