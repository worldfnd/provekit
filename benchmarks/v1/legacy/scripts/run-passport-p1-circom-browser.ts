import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const benchmarkRoot = resolve(import.meta.dir, "..");
const repoRoot = resolve(benchmarkRoot, "../..");
const webRoot = resolve(benchmarkRoot, "circom/web");
const browserRoot = resolve(
  process.env.P1_CIRCOM_BROWSER_ROOT ??
    `${repoRoot}/target/v1-benchmarks/semantic-parity/passport-p1/browser`,
);
const dist = resolve(browserRoot, "dist");
const output = resolve(
  process.env.P1_CIRCOM_BROWSER_REPORT ??
    `${repoRoot}/target/v1-benchmarks/semantic-parity/passport-p1/mac-chrome/circom-snarkjs.json`,
);
const chrome =
  process.env.CHROME_PATH ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

async function commandOutput(args: string[]): Promise<string> {
  const process = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
    process.exited,
  ]);
  if (exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${stderr}`);
  return stdout.trim();
}

for (const required of [
  resolve(dist, "index.html"),
  resolve(dist, "assets/manifest.json"),
  resolve(browserRoot, "fixtures/passport_p1_final.zkey"),
]) {
  if (!(await Bun.file(required).exists())) {
    throw new Error(`missing P1 browser artifact ${required}; run prepare-passport-p1-circom-browser.sh`);
  }
}

const environment = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  ),
  CHROME_PATH: chrome,
  CIRCOM_WEB_DIST: dist,
  MOBENCH_WORKLOAD: "passport",
  MOBENCH_WARMUP: "1",
  MOBENCH_ITERATIONS: "5",
  MOBENCH_SNARKJS_SINGLE_THREAD: "1",
  MOBENCH_TIMEOUT_MS: process.env.MOBENCH_TIMEOUT_MS ?? "900000",
};
const child = Bun.spawn(["bun", "run", "smoke.ts"], {
  cwd: webRoot,
  env: environment,
  stdout: "pipe",
  stderr: "pipe",
});
const [stdout, stderr, exitCode] = await Promise.all([
  new Response(child.stdout).text(),
  new Response(child.stderr).text(),
  child.exited,
]);
if (exitCode !== 0) {
  throw new Error(`P1 Chrome runner failed (${exitCode})\n${stdout}\n${stderr}`);
}

const report = JSON.parse(stdout) as Record<string, unknown>;
const manifest = await Bun.file(resolve(dist, "assets/manifest.json")).json();
const enriched = {
  ...report,
  semantic_profile: "P1",
  benchmark_contract: {
    warmup: 1,
    measured_iterations: 5,
    sequential: true,
    snarkjs_single_thread: true,
    valid_proof_verified_per_sample: true,
    tampered_proof_rejected_per_sample: true,
  },
  browser: {
    name: "Google Chrome",
    version: await commandOutput([chrome, "--version"]),
    headless: true,
  },
  browser_fixture_manifest: manifest,
  runner_stderr: stderr,
};
await mkdir(dirname(output), { recursive: true });
await Bun.write(output, `${JSON.stringify(enriched, null, 2)}\n`);
console.log(output);
