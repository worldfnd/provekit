#!/usr/bin/env bun

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

type BenchReport = {
  function: string;
  spec: {
    name: string;
    iterations: number;
    warmup: number;
  };
  samples_ns: number[];
  samples: Array<{
    duration_ns: number;
    cpu_time_ms?: number;
    process_peak_memory_kb?: number;
  }>;
  resources: {
    process_peak_memory_kb?: number;
  };
};

type SessionRef = {
  id: string;
  status: string;
};

type Build = {
  id: string;
  status: string;
  input_capabilities: {
    app: string;
    testSuite: string;
  };
  devices: Array<{
    device: string;
    os: string;
    os_version: string;
    sessions: SessionRef[];
  }>;
};

type Run = {
  repetition: string;
  build_id: string;
  session_id: string;
  device: string;
  os: string;
  os_version: string;
  samples_ns: number[];
  sample_cpu_time_ms: number[];
  process_peak_memory_kb: number;
};

function usage(): never {
  console.error(
    "usage: summarize-cached-android-recovery.ts ROOT EXPECTED_FUNCTION OUTPUT",
  );
  process.exit(2);
}

function extractBenchReport(log: string): BenchReport {
  const chunks: string[] = [];
  let collecting = false;

  for (const line of log.split(/\r?\n/)) {
    if (line.includes("BENCH_JSON_START")) {
      collecting = true;
      chunks.length = 0;
      continue;
    }
    if (line.includes("BENCH_JSON_END")) {
      break;
    }
    if (!collecting) continue;
    const marker = "BENCH_JSON_CHUNK ";
    const markerIndex = line.indexOf(marker);
    if (markerIndex >= 0) chunks.push(line.slice(markerIndex + marker.length));
  }

  if (chunks.length === 0) {
    throw new Error("device log does not contain a complete BENCH_JSON report");
  }
  return JSON.parse(chunks.join("")) as BenchReport;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? Math.round((sorted[middle - 1] + sorted[middle]) / 2)
    : sorted[middle];
}

const [, , root, expectedFunction, output] = Bun.argv;
if (!root || !expectedFunction || !output) usage();

const repetitions = readdirSync(root, { withFileTypes: true })
  .filter(
    (entry) => entry.isDirectory() && entry.name.startsWith("repetition-"),
  )
  .map((entry) => entry.name)
  .sort();

if (repetitions.length === 0) {
  throw new Error(`no repetition directories found under ${root}`);
}

const runs: Run[] = [];
const buildIds: string[] = [];
const appUrls = new Set<string>();
const testSuiteUrls = new Set<string>();

for (const repetition of repetitions) {
  const repetitionRoot = join(root, repetition);
  const build = JSON.parse(
    readFileSync(join(repetitionRoot, "build.json"), "utf8"),
  ) as Build;
  if (build.status !== "passed") {
    throw new Error(`${repetition} build ${build.id} is ${build.status}`);
  }

  buildIds.push(build.id);
  appUrls.add(build.input_capabilities.app);
  testSuiteUrls.add(build.input_capabilities.testSuite);

  for (const device of build.devices) {
    for (const session of device.sessions) {
      if (session.status !== "passed") {
        throw new Error(
          `${repetition} session ${session.id} is ${session.status}`,
        );
      }
      const logPath = join(repetitionRoot, `device-${session.id}.log`);
      const report = extractBenchReport(readFileSync(logPath, "utf8"));
      if (
        report.function !== expectedFunction ||
        report.spec.name !== expectedFunction
      ) {
        throw new Error(
          `${logPath} returned ${report.function}, expected ${expectedFunction}`,
        );
      }
      if (
        report.spec.iterations !== 2 ||
        report.spec.warmup !== 1 ||
        report.samples_ns.length !== 2
      ) {
        throw new Error(
          `${logPath} does not satisfy the cached 1 warmup + 2 sample contract`,
        );
      }

      const samplePeaks = report.samples
        .map((sample) => sample.process_peak_memory_kb ?? 0)
        .filter((value) => value > 0);
      const reportPeak = report.resources.process_peak_memory_kb ?? 0;
      runs.push({
        repetition,
        build_id: build.id,
        session_id: session.id,
        device: device.device,
        os: device.os,
        os_version: device.os_version,
        samples_ns: report.samples_ns,
        sample_cpu_time_ms: report.samples
          .map((sample) => sample.cpu_time_ms)
          .filter((value): value is number => value !== undefined),
        process_peak_memory_kb: Math.max(reportPeak, ...samplePeaks),
      });
    }
  }
}

const devices = [...new Set(runs.map((run) => run.device))]
  .sort()
  .map((device) => {
    const deviceRuns = runs.filter((run) => run.device === device);
    const samples = deviceRuns.flatMap((run) => run.samples_ns);
    const cpuTimes = deviceRuns.flatMap((run) => run.sample_cpu_time_ms);
    if (deviceRuns.length !== repetitions.length || samples.length !== 6) {
      throw new Error(
        `${device} has ${deviceRuns.length} repetitions and ${samples.length} samples`,
      );
    }
    return {
      device,
      os: deviceRuns[0].os,
      os_version: deviceRuns[0].os_version,
      repetitions: deviceRuns.length,
      warmups: deviceRuns.length,
      sample_count: samples.length,
      samples_ns: samples,
      median_ns: median(samples),
      min_ns: Math.min(...samples),
      max_ns: Math.max(...samples),
      median_cpu_time_ms:
        cpuTimes.length === samples.length ? median(cpuTimes) : null,
      process_peak_memory_kb: Math.max(
        ...deviceRuns.map((run) => run.process_peak_memory_kb),
      ),
      build_ids: deviceRuns.map((run) => run.build_id),
      session_ids: deviceRuns.map((run) => run.session_id),
    };
  });

const summary = {
  schema: "provekit.cached-android-recovery.v1",
  function: expectedFunction,
  sampling_contract: {
    repetitions: repetitions.length,
    warmups_per_repetition: 1,
    measured_samples_per_repetition: 2,
    total_warmups: repetitions.length,
    total_measured_samples: 6,
    note: "This differs from the primary 1 warmup + 5 sample campaign contract.",
  },
  threading: "Android platform-default uncapped Rayon pool",
  artifact_provenance: {
    app_urls: [...appUrls],
    test_suite_urls: [...testSuiteUrls],
    source_sha: null,
    limitation:
      "BrowserStack retained the executable artifacts but not a source SHA or downloadable APK.",
  },
  build_ids: buildIds,
  devices,
  raw_root: basename(root),
};

writeFileSync(output, `${JSON.stringify(summary, null, 2)}\n`);
console.log(`Wrote ${output}`);
