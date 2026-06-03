#!/usr/bin/env node
/**
 * Setup script for the ProveKit browser demo.
 *
 * Usage:
 *   bun scripts/setup.mjs
 *
 * Installs browser dependencies, builds the browser WASM package and native
 * CLI once, then prepares the built-in circuits under artifacts/<name>/.
 */

import { execSync, spawnSync } from "child_process";
import {
  existsSync,
  mkdirSync,
  rmSync,
  copyFileSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "fs";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";
import { parseSimpleToml } from "../shared/toml-parser.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, "../../..");
const DEMO_DIR = resolve(__dirname, "..");
const MAVROS_REV = "171483ed4b88971feb4f958b6e7860b34a216b2d";
const CIRCUITS = [
  { name: "passkey", path: join(ROOT_DIR, "noir-examples/passkey_p256") },
  { name: "webauthn", path: join(ROOT_DIR, "playground/noir-webauthn-demo") },
];

// Colors for console output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  red: "\x1b[31m",
};

function log(msg, color = colors.reset) {
  console.log(`${color}${msg}${colors.reset}`);
}

function logStep(step, msg) {
  console.log(
    `\n${colors.blue}[${step}]${colors.reset} ${colors.bright}${msg}${colors.reset}`
  );
}

function logSuccess(msg) {
  console.log(`${colors.green}✓${colors.reset} ${msg}`);
}

function logError(msg) {
  console.error(`${colors.red}✗ ${msg}${colors.reset}`);
}

function run(cmd, opts = {}) {
  log(`  $ ${cmd}`, colors.yellow);
  try {
    execSync(cmd, { stdio: "inherit", ...opts });
    return true;
  } catch (e) {
    logError(`Command failed: ${cmd}`);
    return false;
  }
}

function truncateOutput(output) {
  const text = String(output ?? "").trim();
  if (text.length <= 800) {
    return text;
  }
  return `...${text.slice(-800)}`;
}

function runArgs(args, opts = {}) {
  log(`  $ ${args.map(shellQuote).join(" ")}`, colors.yellow);
  const result = spawnSync(args[0], args.slice(1), {
    encoding: "utf-8",
    stdio: "pipe",
    ...opts,
  });
  if (result.stdout) {
    process.stdout.write(result.stdout);
  }
  if (result.stderr) {
    process.stderr.write(result.stderr);
  }
  return {
    ok: result.status === 0,
    output: [result.stdout, result.stderr].filter(Boolean).join("\n"),
    status: result.status,
  };
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function checkCommand(cmd, name) {
  const result = spawnSync("which", [cmd], { stdio: "pipe" });
  if (result.status !== 0) {
    logError(`${name} not found. Please install it first.`);
    return false;
  }
  return true;
}

function commandExists(cmd) {
  return spawnSync("which", [cmd], { stdio: "ignore" }).status === 0;
}

function resolvePackageRunner() {
  if (process.env.PROVEKIT_JS_RUNNER) {
    return process.env.PROVEKIT_JS_RUNNER;
  }
  if (commandExists("bun")) {
    return "bun";
  }

  const homeBun = join(process.env.HOME ?? "", ".bun/bin/bun");
  if (existsSync(homeBun)) {
    return homeBun;
  }

  return "npm";
}

function findMavrosManifest() {
  if (process.env.MAVROS_MANIFEST && existsSync(process.env.MAVROS_MANIFEST)) {
    return process.env.MAVROS_MANIFEST;
  }

  const checkoutsDir = join(process.env.HOME ?? "", ".cargo/git/checkouts");
  if (!existsSync(checkoutsDir)) {
    return null;
  }

  for (const repoDir of readdirSync(checkoutsDir)) {
    if (!repoDir.startsWith("mavros-")) {
      continue;
    }
    const repoPath = join(checkoutsDir, repoDir);
    for (const revDir of readdirSync(repoPath)) {
      if (!MAVROS_REV.startsWith(revDir) && !revDir.startsWith(MAVROS_REV.slice(0, 7))) {
        continue;
      }
      const manifest = join(repoPath, revDir, "Cargo.toml");
      if (existsSync(manifest)) {
        return manifest;
      }
    }
  }

  return null;
}

function findMavrosCommand() {
  if (process.env.MAVROS_BIN && existsSync(process.env.MAVROS_BIN)) {
    return [process.env.MAVROS_BIN];
  }

  const manifest = findMavrosManifest();
  if (!manifest) {
    return null;
  }

  for (const profile of ["release", "debug"]) {
    const candidate = join(dirname(manifest), "target", profile, "mavros");
    if (existsSync(candidate)) {
      return [candidate];
    }
  }

  return [
    "cargo",
    "+stable",
    "run",
    "--manifest-path", manifest,
    "-p", "mavros-compiler",
    "--bin", "mavros",
    "--",
  ];
}

/**
 * Get circuit name from Nargo.toml
 */
function getCircuitName(circuitDir) {
  const nargoToml = join(circuitDir, "Nargo.toml");
  if (!existsSync(nargoToml)) {
    throw new Error(`Nargo.toml not found in ${circuitDir}`);
  }

  const content = readFileSync(nargoToml, "utf-8");
  const match = content.match(/^name\s*=\s*"([^"]+)"/m);
  if (!match) {
    throw new Error("Could not find circuit name in Nargo.toml");
  }
  return match[1];
}

async function buildShared() {

  log("\n🔧 ProveKit Browser Demo Setup\n", colors.bright);

  // Check prerequisites
  logStep("1/5", "Checking prerequisites...");
  if (!checkCommand("cargo", "Rust (cargo)")) {
    log("\nInstall Rust: https://rustup.rs");
    process.exit(1);
  }
  logSuccess("cargo found");

  logStep("2/5", "Installing browser dependencies...");
  const packageRunner = resolvePackageRunner();
  const installCommand = packageRunner.endsWith("npm") ? `${packageRunner} install --legacy-peer-deps` : `${packageRunner} install`;
  if (!run(installCommand, { cwd: DEMO_DIR })) {
    process.exit(1);
  }

  // The browser demo loads @noir-lang/* from node_modules directly; the old
  // demo-local vendor/pkg staging directories are no longer needed.
  for (const dir of ["vendor", "pkg", "pkg-web"]) {
    const fullPath = join(DEMO_DIR, dir);
    if (existsSync(fullPath)) {
      rmSync(fullPath, { recursive: true, force: true });
    }
  }
  logSuccess("Removed stale demo-local runtime asset directories");

  logStep("3/5", "Building browser WASM package...");
  if (!run(`${shellQuote(packageRunner)} run wasm:build`, { cwd: DEMO_DIR })) {
    process.exit(1);
  }
  logSuccess("Browser WASM package built");

  // Build native CLI
  logStep("4/5", "Building native CLI...");
  if (!run("cargo build --profile release-fast --bin provekit-cli", { cwd: ROOT_DIR })) {
    process.exit(1);
  }
  logSuccess("Native CLI built");
}

function writeInputsAndMetadata({ artifactsDir, circuitDir, circuitName, backend, label }) {
  const proverTomlSrc = join(circuitDir, "Prover.toml");
  const proverTomlDest = join(artifactsDir, "Prover.toml");
  copyFileSync(proverTomlSrc, proverTomlDest);
  logSuccess("Prover.toml copied");

  const tomlContent = readFileSync(proverTomlSrc, "utf-8");
  const inputs = parseSimpleToml(tomlContent);
  const inputsJsonPath = join(artifactsDir, "inputs.json");
  writeFileSync(inputsJsonPath, JSON.stringify(inputs, null, 2));
  logSuccess("inputs.json created");

  const metadataPath = join(artifactsDir, "metadata.json");
  writeFileSync(
    metadataPath,
    JSON.stringify(
      {
        name: circuitName,
        path: circuitDir,
        backend,
        label,
      },
      null,
      2
    )
  );
  logSuccess("metadata.json created");
}

function writeBackendStatus(artifactsDir, status) {
  writeFileSync(join(artifactsDir, "backend-status.json"), JSON.stringify(status, null, 2));
}

async function prepareAcirCircuit({ name, path: circuitDir }) {
  const artifactsDir = join(DEMO_DIR, "artifacts", name);
  if (!existsSync(artifactsDir)) {
    mkdirSync(artifactsDir, { recursive: true });
  }

  // Validate circuit directory
  if (!existsSync(circuitDir)) {
    logError(`Circuit directory not found: ${circuitDir}`);
    process.exit(1);
  }

  const circuitName = getCircuitName(circuitDir);
  log(`\n📦 Preparing ACIR circuit: ${name} (${circuitName})`, colors.bright);
  log(`   Path: ${circuitDir}`);

  // Prepare prover/verifier artifacts
  logStep(`${name}`, "Preparing prover/verifier artifacts...");
  const cliPath = join(ROOT_DIR, "target/release-fast/provekit-cli");
  const proverBinPath = join(artifactsDir, "prover.pkp");
  const verifierBinPath = join(artifactsDir, "verifier.pkv");

  rmSync(join(artifactsDir, "mavros"), { recursive: true, force: true });
  for (const staleModule of ["witgen.wasm", "witgen.wasm.meta.json", "witgen.ll", "ad.wasm", "ad.wasm.meta.json", "ad.ll"]) {
    rmSync(join(artifactsDir, staleModule), { force: true });
  }

  if (
    !run(
      [
        shellQuote(cliPath),
        "prepare",
        shellQuote(circuitDir),
        "--pkp", shellQuote(proverBinPath),
        "--pkv", shellQuote(verifierBinPath),
        "--hash blake3",
        "--skip-brillig-constraints-check",
      ].join(" "),
      { cwd: artifactsDir }
    )
  ) {
    process.exit(1);
  }
  logSuccess("prover.pkp and verifier.pkv created");


  // Copy Prover.toml and convert to inputs.json
  logStep(`${name}`, "Preparing inputs...");
  writeInputsAndMetadata({
    artifactsDir,
    circuitDir,
    circuitName,
    backend: "acir",
    label: "ACIR / ProveKit v1",
  });
  writeBackendStatus(artifactsDir, {
    available: true,
    backend: "acir",
    label: "ACIR / ProveKit v1",
  });
}

async function prepareMavrosCircuit({ name, path: circuitDir }) {
  const artifactsDir = join(DEMO_DIR, "artifacts", `${name}-mavros`);
  rmSync(artifactsDir, { recursive: true, force: true });
  mkdirSync(artifactsDir, { recursive: true });

  if (!existsSync(circuitDir)) {
    logError(`Circuit directory not found: ${circuitDir}`);
    process.exit(1);
  }

  const circuitName = getCircuitName(circuitDir);
  log(`\n📦 Preparing Mavros circuit: ${name} (${circuitName})`, colors.bright);
  log(`   Path: ${circuitDir}`);

  logStep(`${name}-mavros`, "Preparing inputs...");
  writeInputsAndMetadata({
    artifactsDir,
    circuitDir,
    circuitName,
    backend: "mavros",
    label: "Mavros main",
  });

  const mavrosCommand = findMavrosCommand();
  if (!mavrosCommand) {
    const error = `Mavros ${MAVROS_REV} checkout not found. Set MAVROS_BIN or MAVROS_MANIFEST to enable Mavros comparison artifacts.`;
    logError(error);
    writeBackendStatus(artifactsDir, {
      available: false,
      backend: "mavros",
      label: "Mavros main",
      error,
    });
    return;
  }

  const mavrosDir = join(artifactsDir, "mavros");
  mkdirSync(mavrosDir, { recursive: true });
  const basicPath = join(mavrosDir, "basic.json");
  const r1csPath = join(mavrosDir, "r1cs.bin");

  logStep(`${name}-mavros`, "Compiling Mavros basic/R1CS artifacts...");
  const compileResult = runArgs([
    ...mavrosCommand,
    "compile",
    circuitDir,
    "--r1cs-output", r1csPath,
    "--binary-output", basicPath,
  ], { cwd: artifactsDir });
  if (!compileResult.ok) {
    const error = `Mavros compile failed: ${truncateOutput(compileResult.output)}`;
    logError(error);
    writeBackendStatus(artifactsDir, {
      available: false,
      backend: "mavros",
      label: "Mavros main",
      error,
    });
    return;
  }

  logStep(`${name}-mavros`, "Preparing prover/verifier artifacts...");
  const cliPath = join(ROOT_DIR, "target/release-fast/provekit-cli");
  const proverBinPath = join(artifactsDir, "prover.pkp");
  const verifierBinPath = join(artifactsDir, "verifier.pkv");
  const prepareResult = runArgs([
    cliPath,
    "prepare",
    basicPath,
    "--compiler", "mavros",
    "--r1cs", r1csPath,
    "--pkp", proverBinPath,
    "--pkv", verifierBinPath,
    "--hash", "blake3",
  ], { cwd: artifactsDir });
  if (!prepareResult.ok) {
    const error = `ProveKit Mavros prepare failed: ${truncateOutput(prepareResult.output)}`;
    logError(error);
    writeBackendStatus(artifactsDir, {
      available: false,
      backend: "mavros",
      label: "Mavros main",
      error,
    });
    return;
  }

  writeBackendStatus(artifactsDir, {
    available: false,
    backend: "mavros",
    label: "Mavros main",
    error: "Mavros prover artifacts were prepared, but browser witgen.wasm/ad.wasm modules were not emitted by the available Mavros CLI.",
  });
}

async function main() {
  await buildShared();

  logStep("5/5", `Preparing ${CIRCUITS.length} circuits and comparison backends...`);
  for (const circuit of CIRCUITS) {
    await prepareAcirCircuit(circuit);
    await prepareMavrosCircuit(circuit);
  }

  log("\n\u2705 Setup complete!\n", colors.green + colors.bright);
  log("Run the demo with:", colors.bright);
  log("  bun run serve            # Build and start the browser demo server");
  log("  # Open http://localhost:8080\n");
}

main().catch((err) => {
  logError(err.message);
  process.exit(1);
});
