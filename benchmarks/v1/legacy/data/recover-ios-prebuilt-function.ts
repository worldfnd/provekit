#!/usr/bin/env bun

import { basename, resolve } from "node:path";

interface BenchmarkResult {
  function: string;
  samples: unknown[];
  resources?: { process_peak_memory_kb?: number; peak_memory_kb?: number };
  [key: string]: unknown;
}

export function extractBenchmarkResult(
  logs: string[],
  expectedFunction: string,
): BenchmarkResult {
  const matches: BenchmarkResult[] = [];
  for (const log of logs) {
    for (const line of log.split(/\r?\n/)) {
      const start = line.indexOf("{");
      if (start < 0) continue;
      try {
        const value = JSON.parse(line.slice(start)) as BenchmarkResult;
        if (
          value.function === expectedFunction &&
          Array.isArray(value.samples) &&
          value.samples.length === 5
        ) {
          matches.push(value);
        }
      } catch {
        // Xcode instrumentation logs contain ordinary prose and truncated
        // attachment lines. Only complete benchmark JSON objects are evidence.
      }
    }
  }
  if (matches.length === 0) {
    throw new Error(`no five-sample benchmark JSON found for ${expectedFunction}`);
  }
  const canonical = JSON.stringify(matches[0]);
  if (matches.some((match) => JSON.stringify(match) !== canonical)) {
    throw new Error(`conflicting benchmark JSON found for ${expectedFunction}`);
  }
  return matches[0]!;
}

if (import.meta.main) {
  const [
    artifactRootArg,
    manifestPath,
    expectedFunction,
    outputPath,
    device = "iPhone SE 2022-15",
  ] = process.argv.slice(2);
  if (!artifactRootArg || !manifestPath || !expectedFunction || !outputPath) {
    console.error(
      "usage: bun recover-ios-prebuilt-function.ts <artifact-root> <manifest.json> <function> <output.json> [device]",
    );
    process.exit(2);
  }
  const artifactRoot = resolve(artifactRootArg);
  const manifest = (await Bun.file(manifestPath).json()) as {
    entries: Array<{ function: string; iterations: number; warmup: number }>;
  };
  const entry = manifest.entries.find(
    (candidate) => candidate.function === expectedFunction,
  );
  if (!entry || entry.iterations !== 5 || entry.warmup !== 1) {
    throw new Error(`${expectedFunction}: missing or invalid prebuilt manifest entry`);
  }
  const glob = new Bun.Glob("**/*instrumentation_log.log");
  const logPaths = Array.from(glob.scanSync({ cwd: artifactRoot, absolute: true }));
  const logs = await Promise.all(logPaths.map((path) => Bun.file(path).text()));
  const result = extractBenchmarkResult(logs, expectedFunction);
  const peakKb =
    result.resources?.process_peak_memory_kb ??
    result.resources?.peak_memory_kb;
  const summary = {
    schema: "provekit.recovered-ios-prebuilt-function.v1",
    evidence_root: artifactRoot,
    functions: {
      [expectedFunction]: {
        spec: { iterations: entry.iterations, warmup: entry.warmup },
        remote_run: { build_id: basename(artifactRoot) },
        benchmark_results: { [device]: [result] },
        performance_metrics: {
          [device]: {
            memory: {
              peak_mb: typeof peakKb === "number" ? peakKb / 1024 : null,
            },
          },
        },
      },
    },
  };
  await Bun.write(outputPath, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`recovered ${expectedFunction} to ${outputPath}`);
}
