#!/usr/bin/env bun

import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "../../..");
const adb = process.env.ADB ?? resolve(process.env.HOME!, "Library/Android/sdk/platform-tools/adb");
const serial = process.env.ANDROID_SERIAL ?? "ZY32M6782K";
const packageId = process.env.TACEO_ANDROID_PACKAGE ?? "dev.world.zkmobilebench";
const activityClass = process.env.TACEO_ANDROID_ACTIVITY ?? "dev.world.zkmobilebench.MainActivity";
const only = process.env.TACEO_ONLY?.split(",").filter(Boolean);
const apk = resolve(
  process.env.TACEO_ANDROID_APK ??
    resolve(repoRoot, "target/v1-benchmarks/taceo-oprf-android-v2/android/app/build/outputs/apk/debug/app-debug.apk"),
);
const outputRoot = resolve(
  process.env.TACEO_E15_OUTPUT ??
    resolve(repoRoot, "target/v1-benchmarks/taceo-v021/evidence/e15-taceo-oprf"),
);
const timeoutSeconds = Number(process.env.TACEO_TIMEOUT_SECONDS ?? "7200");
const samples = Number(process.env.TACEO_SAMPLES ?? "5");
const requestedCircuit = process.env.TACEO_CIRCUIT;

const allFunctions = [
  ["oprf_query", "warm", "zk_mobile_bench::bench_taceo_oprf_query_input_to_proof", 1],
  ["oprf_query", "cold", "zk_mobile_bench::bench_taceo_oprf_query_input_to_proof_cold", 0],
  ["oprf_nullifier", "warm", "zk_mobile_bench::bench_taceo_oprf_input_to_proof", 1],
  ["oprf_nullifier", "cold", "zk_mobile_bench::bench_taceo_oprf_input_to_proof_cold", 0],
] as const;
if (requestedCircuit && requestedCircuit !== "oprf_query" && requestedCircuit !== "oprf_nullifier") {
  throw new Error("TACEO_CIRCUIT must be oprf_query or oprf_nullifier");
}
const functions = requestedCircuit ? allFunctions.filter(([circuit]) => circuit === requestedCircuit) : allFunctions;

async function command(args: string[], allowFailure = false): Promise<string> {
  const child = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0 && !allowFailure) {
    throw new Error(`${args.join(" ")} failed (${exitCode})\n${stderr}\n${stdout}`);
  }
  return `${stdout}${stderr}`;
}

function parseBenchJson(log: string): unknown {
  const lines = log.split(/\r?\n/);
  const singleLine = lines.findLast((line) => line.includes("BENCH_JSON "));
  if (singleLine && !singleLine.includes("BENCH_JSON_START")) {
    return JSON.parse(singleLine.slice(singleLine.indexOf("BENCH_JSON ") + "BENCH_JSON ".length));
  }
  const end = lines.findLastIndex((line) => line.includes("BENCH_JSON_END"));
  const start = lines.findLastIndex((line, index) => index < end && line.includes("BENCH_JSON_START"));
  if (start < 0 || end < 0) throw new Error("logcat has no complete BENCH_JSON record");
  const chunks = lines
    .slice(start + 1, end)
    .filter((line) => line.includes("BENCH_JSON_CHUNK "))
    .map((line) => line.slice(line.indexOf("BENCH_JSON_CHUNK ") + "BENCH_JSON_CHUNK ".length));
  if (chunks.length === 0) throw new Error("logcat has no BENCH_JSON_CHUNK records");
  return JSON.parse(chunks.join(""));
}

function parseFailureJson(log: string): unknown | null {
  const line = log.split(/\r?\n/).findLast((candidate) => candidate.includes("BENCH_FAILURE_JSON "));
  return line ? JSON.parse(line.slice(line.indexOf("BENCH_FAILURE_JSON ") + "BENCH_FAILURE_JSON ".length)) : null;
}

async function hash(path: string) {
  const bytes = new Uint8Array(await Bun.file(path).arrayBuffer());
  return {
    path,
    size_bytes: bytes.byteLength,
    sha256: new Bun.CryptoHasher("sha256").update(bytes).digest("hex"),
  };
}

async function logcat() {
  return command([
    adb, "-s", serial, "logcat", "-d", "-v", "epoch",
    "BenchRunner:I", "lowmemorykiller:I", "ActivityManager:I", "AndroidRuntime:E", "libc:E", "*:S",
  ]);
}

async function waitForReport(functionName: string) {
  const started = Date.now();
  let log = "";
  while (Date.now() - started < timeoutSeconds * 1000) {
    log = await logcat();
    if (log.includes("BENCH_JSON_END") || log.includes("BENCH_JSON ") || log.includes("BENCH_FAILURE_JSON ")) return { log, functionName };
    await Bun.sleep(2000);
  }
  return { log, functionName };
}

async function deviceIdentity() {
  const properties = [
    ["manufacturer", "ro.product.manufacturer"],
    ["model", "ro.product.model"],
    ["os_version", "ro.build.version.release"],
    ["abi", "ro.product.cpu.abi"],
    ["abilist", "ro.product.cpu.abilist"],
    ["abilist64", "ro.product.cpu.abilist64"],
    ["zygote", "ro.zygote"],
  ] as const;
  return Object.fromEntries(await Promise.all(properties.map(async ([key, property]) => [
    key, (await command([adb, "-s", serial, "shell", "getprop", property])).trim(),
  ])));
}

async function main() {
  if (!Number.isInteger(samples) || samples <= 0) throw new Error("TACEO_SAMPLES must be positive");
  await mkdir(outputRoot, { recursive: true });
  const identity = await deviceIdentity();
  const apkMeta = await hash(apk);
  const libraryPaths = [
    resolve(repoRoot, "benchmarks/v1/circom/taceo-mobile/target/armv7-linux-androideabi/release/libzk_mobile_bench.so"),
    resolve(repoRoot, "benchmarks/v1/circom/taceo-mobile/target/aarch64-linux-android/release/libzk_mobile_bench.so"),
  ];
  const libraryMeta = [];
  for (const path of libraryPaths) {
    if (await Bun.file(path).exists()) libraryMeta.push(await hash(path));
  }
  await Bun.write(resolve(outputRoot, "device.json"), `${JSON.stringify({ captured_at_utc: new Date().toISOString(), serial, ...identity }, null, 2)}\n`);

  for (const [circuit, mode, functionName, warmup] of functions.filter(([circuit, mode]) =>
    !only || only.includes(`${circuit}__${mode}`),
  )) {
    const id = `${circuit}__${mode}`;
    const dir = resolve(outputRoot, id);
    await mkdir(dir, { recursive: true });
    await command([adb, "-s", serial, "uninstall", packageId], true);
    await command([adb, "-s", serial, "install", "-r", "-t", apk]);
    await command([adb, "-s", serial, "logcat", "-c"]);
    await command([adb, "-s", serial, "shell", "am", "force-stop", packageId], true);
    await command([
      adb, "-s", serial, "shell", "am", "start", "-W", "-n", `${packageId}/${activityClass}`,
      "--es", "bench_function", functionName,
      "--ei", "bench_iterations", String(samples),
      "--ei", "bench_warmup", String(warmup),
      "--el", "bench_timeout_secs", String(timeoutSeconds),
      "--el", "bench_heartbeat_interval_secs", "10",
    ]);
    const result = await waitForReport(functionName);
    await Bun.write(resolve(dir, "raw-logcat.txt"), result.log);
    const parsed = result.log.includes("BENCH_JSON_END") || result.log.includes("BENCH_JSON ")
      ? parseBenchJson(result.log)
      : null;
    const failure = parsed === null ? parseFailureJson(result.log) : null;
    const payload = {
      schema_version: "provekit.taceo-oprf-e15.v1",
      created_at_utc: new Date().toISOString(),
      target: "motorola_e15",
      serial,
      circuit,
      mode,
      function: functionName,
      contract: { warmup, measured_samples: samples },
      source: {
        circom_helpers_main: "8aacd73ed6ab0a2b9b2158e613acfa920860865a",
        circom_witness_rs_branch: "codex/remove-cxx-bridge-and-grep",
        circom_witness_rs_commit: "e11206a9f453145dcd6b814523cbfba4f60cf5c6",
        circom: "2.2.2",
        taceo_groth16: "0.2.1",
        taceo_groth16_material: "0.4.2",
      },
      device: identity,
      artifacts: { apk: apkMeta, native_libraries: libraryMeta },
      status: parsed ? "ok" : failure ? "runtime_failed" : "timed_out",
      report: parsed,
      failure,
      raw_logcat: "raw-logcat.txt",
    };
    await Bun.write(resolve(dir, "evidence.json"), `${JSON.stringify(payload, null, 2)}\n`);
    if (!parsed) throw new Error(`${id} did not produce a valid report; see ${dir}/raw-logcat.txt`);
    const report = parsed as { samples?: Array<Record<string, unknown>> };
    if (!Array.isArray(report.samples) || report.samples.length !== samples) {
      throw new Error(`${id} produced ${report.samples?.length ?? 0} measured samples, expected ${samples}`);
    }
    console.log(`${id}: ${resolve(dir, "evidence.json")}`);
  }
}

await main();
