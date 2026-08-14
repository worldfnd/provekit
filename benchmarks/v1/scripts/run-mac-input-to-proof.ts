import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  PROFILES, STACKS, TIMING_MODES, seriesId,
  type Profile, type Stack, type TimingMode,
} from "../input-to-proof-data/schema";

const benchmarkRoot = resolve(import.meta.dir, "..");
const executionPolicy = process.env.INPUT_TO_PROOF_EXECUTION_POLICY === "singlethread"
  ? "singlethread"
  : "multithread";
const outputRoot = resolve(
  process.env.INPUT_TO_PROOF_OUTPUT_ROOT ??
    resolve(benchmarkRoot, executionPolicy === "multithread"
      ? "../../target/v1-benchmarks/input-to-proof/mac-chrome-multithread"
      : "../../target/v1-benchmarks/input-to-proof/mac-chrome"),
);
const campaignId = process.env.INPUT_TO_PROOF_CAMPAIGN_ID ??
  (executionPolicy === "multithread"
    ? "input-to-proof-v1-mac-multithread-16-20260812"
    : "input-to-proof-v1-20260807");
const force = process.argv.includes("--force");
const only = process.env.INPUT_TO_PROOF_SERIES;

async function checked(args: string[]) {
  const child = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  if (exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${stderr}`);
  return stdout.trim();
}

const chrome = process.env.CHROME_PATH ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const hostEnvironment = {
  device_model: "MacBook Pro (Apple M4 Max)",
  os_version: `${await checked(["sw_vers", "-productVersion"])} (${await checked(["sw_vers", "-buildVersion"])})`,
  abi: await checked(["uname", "-m"]),
  browser: await checked([chrome, "--version"]),
};

const workload: Record<Profile, Record<Stack, string>> = {
  passport_complete_age_check: {
    provekit_v1: "passport_complete_age_check",
    noir_barretenberg: "passport_complete_age_check",
    circom_groth16: "passport",
  },
  passport_p1: {
    provekit_v1: "passport_p1",
    noir_barretenberg: "passport_p1",
    circom_groth16: "passport",
  },
  oprf_o2: {
    provekit_v1: "oprf_taceo",
    noir_barretenberg: "oprf_world_id_nullifier",
    circom_groth16: "oprf",
  },
  webauthn_closest_analogue: {
    provekit_v1: "webauthn_assertion",
    noir_barretenberg: "webauthn_assertion",
    circom_groth16: "webauthn",
  },
};

function command(stack: Stack): { cwd: string; args: string[] } {
  if (stack === "provekit_v1") {
    return { cwd: resolve(benchmarkRoot, "wasm"), args: ["bun", "run", "scripts/smoke.ts"] };
  }
  if (stack === "noir_barretenberg") {
    return { cwd: resolve(benchmarkRoot, "barretenberg"), args: ["bun", "run", "web/smoke.ts"] };
  }
  return { cwd: resolve(benchmarkRoot, "circom/web"), args: ["bun", "run", "smoke.ts"] };
}

async function runOnce(profile: Profile, stack: Stack, mode: TimingMode) {
  const spec = command(stack);
  const env: Record<string, string> = {
    ...Object.fromEntries(Object.entries(process.env).filter((e): e is [string, string] => e[1] !== undefined)),
    MOBENCH_WORKLOAD: workload[profile][stack],
    MOBENCH_WARMUP: mode === "warm_reuse" ? "1" : "0",
    MOBENCH_ITERATIONS: mode === "warm_reuse" ? "5" : "1",
    MOBENCH_TIMING_MODE: mode,
    MOBENCH_SNARKJS_SINGLE_THREAD: executionPolicy === "singlethread" ? "1" : "0",
    // The canonical campaign is fixed at 16 workers. An explicit single-thread
    // policy remains available for historical diagnostics only.
    MOBENCH_SNARKJS_THREADS: process.env.MOBENCH_SNARKJS_THREADS ?? (executionPolicy === "multithread" ? "16" : "1"),
    MOBENCH_WASM_THREAD_MODE: executionPolicy,
    MOBENCH_WASM_THREADS: process.env.MOBENCH_WASM_THREADS ?? (executionPolicy === "multithread" ? "16" : "single"),
    MOBENCH_BARRETENBERG_THREAD_MODE: executionPolicy,
    MOBENCH_BB_THREADS: executionPolicy === "multithread" ? "32" : "1",
    MOBENCH_TIMEOUT_MS: "3600000",
  };
  if (stack === "circom_groth16" && profile === "passport_p1") {
    env.CIRCOM_WEB_DIST = resolve(
      benchmarkRoot,
      "../../target/v1-benchmarks/circom-browser-p1/dist",
    );
  }
  const child = Bun.spawn(spec.args, { cwd: spec.cwd, env, stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) throw new Error(`${spec.args.join(" ")} failed (${exitCode})\n${stderr}\n${stdout}`);
  return { report: JSON.parse(stdout), stderr };
}

await mkdir(outputRoot, { recursive: true });
for (const profile of PROFILES) {
  for (const stack of STACKS) {
    for (const mode of TIMING_MODES) {
      const id = seriesId(profile, "mac_chrome", stack, mode);
      if (only && id !== only) continue;
      const output = resolve(outputRoot, `${id}.json`);
      if (!force && await Bun.file(output).exists()) {
        const existing = await Bun.file(output).json().catch(() => null) as { campaign_id?: string; execution_policy?: string } | null;
        if (existing?.campaign_id === campaignId && existing.execution_policy === executionPolicy) {
          console.error(`[skip] ${id}`);
          continue;
        }
        console.error(`[rerun] ${id}: existing evidence has a different campaign/policy`);
      }
      console.error(`[run] ${id}`);
      const attempts = [];
      const count = mode === "cold_local" ? 6 : 1;
      for (let index = 0; index < count; index += 1) {
        console.error(`  attempt ${index + 1}/${count}`);
        const result = await runOnce(profile, stack, mode);
        attempts.push({
          attempt_index: index,
          warmup: mode === "cold_local" ? index === 0 : null,
          ...result,
        });
      }
      const series = {
        schema_version: 1,
        campaign_id: campaignId,
        series_id: id,
        semantic_profile: profile,
        target: "mac_chrome",
        stack,
        timing_mode: mode,
        execution_policy: executionPolicy,
        environment: hostEnvironment,
        created_at: new Date().toISOString(),
        attempts,
      };
      await mkdir(dirname(output), { recursive: true });
      await Bun.write(output, `${JSON.stringify(series, null, 2)}\n`);
    }
  }
}
