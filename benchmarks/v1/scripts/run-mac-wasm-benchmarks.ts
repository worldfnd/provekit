import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const scriptDirectory = dirname(new URL(import.meta.url).pathname);
const benchmarkRoot = resolve(scriptDirectory, "..");
const repoRoot = resolve(benchmarkRoot, "../..");
const output = resolve(
  process.env.MAC_WASM_BENCHMARK_JSON ??
    `${benchmarkRoot}/results/run-30041758043/mac-chrome-wasm-benchmarks.json`,
);
const chrome =
  process.env.CHROME_PATH ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const workloads = [
  "passport_complete_age_check",
  "webauthn_assertion",
  "oprf_taceo",
];

function environment(extra: Record<string, string> = {}): Record<string, string> {
  return {
    ...Object.fromEntries(
      Object.entries(process.env).filter(
        (entry): entry is [string, string] => entry[1] !== undefined,
      ),
    ),
    CHROME_PATH: chrome,
    MOBENCH_WARMUP: "1",
    MOBENCH_ITERATIONS: "5",
    ...extra,
  };
}

async function runJson(
  args: string[],
  cwd: string,
  extraEnvironment: Record<string, string>,
): Promise<unknown> {
  const child = Bun.spawn(args, {
    cwd,
    env: environment(extraEnvironment),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(`${args.join(" ")} failed (${exitCode})\n${stdout}\n${stderr}`);
  }
  return JSON.parse(stdout);
}

async function checked(args: string[]): Promise<string> {
  const child = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) throw new Error(`${args.join(" ")} failed\n${stderr}`);
  return stdout.trim();
}

if (!(await Bun.file(chrome).exists())) {
  throw new Error(`Google Chrome was not found at ${chrome}`);
}
for (const required of [
  resolve(benchmarkRoot, "wasm/dist/manifest.json"),
  resolve(benchmarkRoot, "barretenberg/web/dist/index.html"),
  resolve(benchmarkRoot, "circom/web/dist/assets/manifest.json"),
]) {
  if (!(await Bun.file(required).exists())) {
    throw new Error(`missing built browser fixture ${required}; follow REPRODUCIBILITY.md`);
  }
}

const provekit = [];
for (const workload of workloads) {
  console.error(`[Chrome WASM] ProveKit ${workload}`);
  provekit.push(
    await runJson(
      ["bun", "run", "scripts/smoke.ts"],
      resolve(benchmarkRoot, "wasm"),
      { MOBENCH_WORKLOAD: workload },
    ),
  );
}

const barretenberg = [];
for (const workload of workloads) {
  console.error(`[Chrome WASM] Barretenberg ${workload}`);
  barretenberg.push(
    await runJson(
      ["bun", "run", "web/smoke.ts"],
      resolve(benchmarkRoot, "barretenberg"),
      { MOBENCH_WORKLOAD: workload, BARRETENBERG_BENCH_PORT: "0" },
    ),
  );
}

const circom = [];
for (const workload of ["passport", "webauthn", "oprf"]) {
  console.error(`[Chrome WASM] Circom/SnarkJS ${workload}`);
  circom.push(
    await runJson(
      ["bun", "run", "smoke.ts"],
      resolve(benchmarkRoot, "circom/web"),
      { MOBENCH_WORKLOAD: workload },
    ),
  );
}

const report = {
  schema_version: 1,
  generated_at: new Date().toISOString(),
  environment: {
    hardware: await checked(["sysctl", "-n", "machdep.cpu.brand_string"]),
    memory_bytes: Number.parseInt(await checked(["sysctl", "-n", "hw.memsize"]), 10),
    os: `${await checked(["sw_vers", "-productName"])} ${await checked([
      "sw_vers",
      "-productVersion",
    ])}`,
    os_build: await checked(["sw_vers", "-buildVersion"]),
    architecture: await checked(["uname", "-m"]),
    browser: await checked([chrome, "--version"]),
    headless: true,
  },
  contract: {
    sequential: true,
    browser: "Google Chrome only",
    warmup: 1,
    measured_iterations: 5,
    wasm_threads: false,
    process_peak_memory: null,
    memory_limitation:
      "Chrome does not expose reliable renderer-process peak RSS to page JavaScript.",
  },
  results: { provekit, barretenberg, circom },
};

await mkdir(dirname(output), { recursive: true });
await Bun.write(output, `${JSON.stringify(report, null, 2)}\n`);
console.log(output);
