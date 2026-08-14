#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { copyFile, mkdir, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

type Platform = "ios" | "android";

const functions = new Set([
  "provekit_v1_barretenberg_mobile::bench_passport_barretenberg_prove",
  "provekit_v1_barretenberg_mobile::bench_passport_barretenberg_verify",
  "provekit_v1_barretenberg_mobile::bench_passport_barretenberg_e2e",
  "provekit_v1_barretenberg_mobile::bench_webauthn_barretenberg_prove",
  "provekit_v1_barretenberg_mobile::bench_webauthn_barretenberg_verify",
  "provekit_v1_barretenberg_mobile::bench_webauthn_barretenberg_e2e",
  "provekit_v1_barretenberg_mobile::bench_oprf_barretenberg_prove",
  "provekit_v1_barretenberg_mobile::bench_oprf_barretenberg_verify",
  "provekit_v1_barretenberg_mobile::bench_oprf_barretenberg_e2e",
]);

function usage(): never {
  throw new Error(
    "usage: prepare-barretenberg-mobile-run.ts --platform <ios|android> " +
      "--app-root <directory> --function <name> --iterations <count> " +
      "--warmup <count> [--archive <ipa|aab>] [--output <evidence.json>] " +
      "[--app-apk <apk> --test-apk <apk> --prebuilt-output <directory>]",
  );
}

function parseInteger(value: string | undefined, name: string): number {
  if (!value || !/^\d+$/.test(value)) usage();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`invalid --${name}`);
  return parsed;
}

const values = new Map<string, string>();
const args = Bun.argv.slice(2);
for (let index = 0; index < args.length; index += 2) {
  const flag = args[index];
  const value = args[index + 1];
  if (!flag?.startsWith("--") || !value) usage();
  values.set(flag.slice(2), value);
}

const platform = values.get("platform");
const appRoot = values.get("app-root");
const functionName = values.get("function");
if (
  (platform !== "ios" && platform !== "android") ||
  !appRoot ||
  !functionName ||
  !functions.has(functionName)
) {
  usage();
}
const iterations = parseInteger(values.get("iterations"), "iterations");
const warmup = parseInteger(values.get("warmup"), "warmup");
if (iterations < 1) throw new Error("--iterations must be at least 1");

const spec = {
  function: functionName,
  iterations,
  warmup,
  android_benchmark_timeout_secs: 7200,
  android_heartbeat_interval_secs: 10,
};
const specBytes = `${JSON.stringify(spec, null, 2)}\n`;
const specSha256 = createHash("sha256").update(specBytes).digest("hex");
const resolvedAppRoot = resolve(appRoot);
const specPath =
  platform === "ios"
    ? join(resolvedAppRoot, "BenchRunner/BenchRunner/Resources/bench_spec.json")
    : join(resolvedAppRoot, "app/src/main/assets/bench_spec.json");
await mkdir(resolve(specPath, ".."), { recursive: true });
await Bun.write(specPath, specBytes);

let archiveEvidence:
  | { path: string; bytes: number; sha256: string; entry: string }
  | undefined;
const archive = values.get("archive");
if (archive) {
  const resolvedArchive = resolve(archive);
  const entry =
    platform === "ios"
      ? "Payload/BenchRunner.app/bench_spec.json"
      : "base/assets/bench_spec.json";
  const extracted = Bun.spawnSync(["unzip", "-p", resolvedArchive, entry]);
  if (extracted.exitCode !== 0 || extracted.stdout.length === 0) {
    throw new Error(`${basename(resolvedArchive)} has no ${entry}`);
  }
  const embedded = extracted.stdout.toString();
  if (embedded !== specBytes) {
    throw new Error(`${basename(resolvedArchive)} benchmark spec mismatch`);
  }
  const archiveBytes = new Uint8Array(
    await Bun.file(resolvedArchive).arrayBuffer(),
  );
  archiveEvidence = {
    path: resolvedArchive,
    bytes: archiveBytes.length,
    sha256: createHash("sha256").update(archiveBytes).digest("hex"),
    entry,
  };
}

const evidence = {
  schema: "provekit.barretenberg-mobile-run-spec.v1",
  platform,
  spec,
  spec_path: specPath,
  spec_sha256: specSha256,
  archive: archiveEvidence,
};
const appApk = values.get("app-apk");
const testApk = values.get("test-apk");
const prebuiltOutput = values.get("prebuilt-output");
if (appApk || testApk || prebuiltOutput) {
  if (platform !== "android" || !appApk || !testApk || !prebuiltOutput) {
    throw new Error(
      "--app-apk, --test-apk, and --prebuilt-output are Android-only and must be used together",
    );
  }
  const resolvedPrebuilt = resolve(prebuiltOutput);
  const entryRoot = join(resolvedPrebuilt, "entries/0000");
  await mkdir(entryRoot, { recursive: true });
  const artifacts = [];
  for (const input of [
    { kind: "android-app", source: resolve(appApk), name: "app.apk" },
    {
      kind: "android-test-suite",
      source: resolve(testApk),
      name: "test.apk",
    },
  ]) {
    const destination = join(entryRoot, input.name);
    await copyFile(input.source, destination);
    const metadata = await stat(destination);
    const bytes = new Uint8Array(await Bun.file(destination).arrayBuffer());
    artifacts.push({
      kind: input.kind,
      path: `entries/0000/${input.name}`,
      size: metadata.size,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  }
  const git = Bun.spawnSync(["git", "rev-parse", "HEAD"]);
  const sourceSha = git.stdout.toString().trim();
  if (git.exitCode !== 0 || !/^[0-9a-f]{40}$/.test(sourceSha)) {
    throw new Error("cannot resolve a full source commit SHA");
  }
  const manifest = {
    schema: "mobench.prebuilt.v1",
    source_sha: sourceSha,
    platform: "android",
    mobench_version: "0.1.48",
    entries: [
      {
        function: functionName,
        iterations,
        warmup,
        completion_timeout_secs: 7200,
        artifacts,
      },
    ],
  };
  await Bun.write(
    join(resolvedPrebuilt, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
}
const output = values.get("output");
if (output) {
  const resolvedOutput = resolve(output);
  await mkdir(resolve(resolvedOutput, ".."), { recursive: true });
  await Bun.write(resolvedOutput, `${JSON.stringify(evidence, null, 2)}\n`);
}
console.log(JSON.stringify(evidence, null, 2));
