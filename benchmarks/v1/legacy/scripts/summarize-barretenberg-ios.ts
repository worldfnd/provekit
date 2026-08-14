#!/usr/bin/env bun

import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";

type Benchmark = {
  function: string;
  samples: number;
  mean_ns: number;
  median_ns: number;
  p95_ns: number;
  min_ns: number;
  max_ns: number;
  resource_usage: {
    peak_memory_kb: number;
    peak_memory_growth_kb: number;
    process_peak_memory_kb: number;
  };
};

type Run = {
  spec: {
    function: string;
    iterations: number;
    warmup: number;
    devices: string[];
    ios_deployment_target: string;
  };
  remote_run: { build_id: string };
  summary: {
    device_summaries: Array<{
      device: string;
      benchmarks: Benchmark[];
    }>;
  };
};

const resultRoot = resolve(
  Bun.argv[2] ??
    "benchmarks/v1/results/run-30041758043/barretenberg-mobile-release",
);
const output = resolve(
  Bun.argv[3] ?? join(resultRoot, "ios-v3-summary.json"),
);
const cases = [
  ["passport", "prove", "ios-passport-prove-v3-1x5.json"],
  ["passport", "verify", "ios-passport-verify-v3-1x5.json"],
  ["passport", "e2e", "ios-passport-e2e-v3-1x5.json"],
  ["webauthn", "prove", "ios-webauthn-prove-v3-1x5.json"],
  ["webauthn", "verify", "ios-webauthn-verify-v3-1x5.json"],
  ["webauthn", "e2e", "ios-webauthn-e2e-v3-1x5.json"],
  ["oprf", "prove", "ios-oprf-prove-v3-1x5.json"],
  ["oprf", "verify", "ios-oprf-verify-v3-1x5.json"],
  ["oprf", "e2e", "ios-oprf-e2e-v3-1x5.json"],
] as const;

const results = [];
for (const [workload, phase, filename] of cases) {
  const path = join(resultRoot, filename);
  const run = (await Bun.file(path).json()) as Run;
  const benchmark = run.summary.device_summaries[0]?.benchmarks[0];
  if (
    run.spec.iterations !== 5 ||
    run.spec.warmup !== 1 ||
    run.spec.devices.length !== 1 ||
    run.spec.ios_deployment_target !== "15.0" ||
    !benchmark ||
    benchmark.function !== run.spec.function ||
    benchmark.samples !== 5
  ) {
    throw new Error(`${filename} does not satisfy the iOS 1+5 contract`);
  }
  results.push({
    workload,
    phase,
    function: benchmark.function,
    device: run.summary.device_summaries[0]!.device,
    iterations: run.spec.iterations,
    warmup: run.spec.warmup,
    mean_ns: benchmark.mean_ns,
    median_ns: benchmark.median_ns,
    p95_ns: benchmark.p95_ns,
    min_ns: benchmark.min_ns,
    max_ns: benchmark.max_ns,
    peak_memory_kb: benchmark.resource_usage.peak_memory_kb,
    peak_memory_growth_kb: benchmark.resource_usage.peak_memory_growth_kb,
    process_peak_memory_kb: benchmark.resource_usage.process_peak_memory_kb,
    browserstack_build_id: run.remote_run.build_id,
    source: filename,
  });
}

const summary = {
  schema: "provekit.barretenberg-v087-ios-summary.v1",
  campaign: "provekit-v1",
  backend: "barretenberg",
  backend_version: "0.87.0",
  noir_version: "1.0.0-beta.11",
  platform: "ios",
  device: "iPhone SE 2022",
  os: "15.4",
  warmup: 1,
  iterations: 5,
  timing_unit: "ns",
  results,
};
await mkdir(resolve(output, ".."), { recursive: true });
await Bun.write(output, `${JSON.stringify(summary, null, 2)}\n`);
console.log(output);
