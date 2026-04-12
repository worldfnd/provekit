#!/usr/bin/env python3

import csv
import json
import os
import sys
from tempfile import NamedTemporaryFile


def usage() -> int:
    print(
        "usage: enrich_mobench_results_csv.py <summary-json> <results-csv>",
        file=sys.stderr,
    )
    return 2


def load_summary_index(summary_path: str) -> dict[tuple[str, str], dict[str, object]]:
    with open(summary_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    root = payload.get("summary", payload)
    device_summaries = root.get("device_summaries") or []
    index: dict[tuple[str, str], dict[str, object]] = {}

    for device_summary in device_summaries:
        device_name = device_summary.get("device")
        if not device_name:
            continue
        for benchmark in device_summary.get("benchmarks") or []:
            function_name = benchmark.get("function")
            if not function_name:
                continue
            resource_usage = benchmark.get("resource_usage") or {}
            index[(str(device_name), str(function_name))] = {
                "cpu_total_ms": resource_usage.get("cpu_total_ms"),
                "peak_memory_kb": resource_usage.get("peak_memory_kb"),
            }

    return index


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return usage()

    summary_path, csv_path = argv[1], argv[2]
    if not os.path.exists(summary_path) or not os.path.exists(csv_path):
        return 0

    summary_index = load_summary_index(summary_path)

    with open(csv_path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    if not fieldnames:
        return 0

    for field in ("cpu_total_ms", "peak_memory_kb"):
        if field not in fieldnames:
            fieldnames.append(field)

    for row in rows:
        key = (row.get("device", ""), row.get("function", ""))
        resource_usage = summary_index.get(key)
        if not resource_usage:
            continue

        cpu_total_ms = resource_usage.get("cpu_total_ms")
        peak_memory_kb = resource_usage.get("peak_memory_kb")
        if cpu_total_ms is not None and not row.get("cpu_total_ms"):
            row["cpu_total_ms"] = str(cpu_total_ms)
        if peak_memory_kb is not None and not row.get("peak_memory_kb"):
            row["peak_memory_kb"] = str(peak_memory_kb)

    with NamedTemporaryFile(
        "w", encoding="utf-8", newline="", delete=False, dir=os.path.dirname(csv_path) or "."
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        temp_path = handle.name

    os.replace(temp_path, csv_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
