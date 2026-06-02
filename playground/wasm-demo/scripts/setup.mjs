#!/usr/bin/env node
/**
 * Setup script for the ProveKit browser demo.
 *
 * Usage:
 *   node scripts/setup.mjs
 *
 * Installs browser dependencies, builds the native CLI once, then prepares
 * SHA256, Poseidon, and passkey circuits into artifacts/<name>/.
 */

import { execSync, spawnSync } from "child_process";
import {
  existsSync,
  mkdirSync,
  rmSync,
  copyFileSync,
  cpSync,
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
const CIRCUITS = [
  { name: "sha256",   path: join(ROOT_DIR, "noir-examples/noir_sha256") },
  { name: "poseidon", path: join(ROOT_DIR, "noir-examples/poseidon-rounds") },
  { name: "passkey",  path: join(ROOT_DIR, "noir-examples/passkey_p256") },
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

function checkCommand(cmd, name) {
  const result = spawnSync("which", [cmd], { stdio: "pipe" });
  if (result.status !== 0) {
    logError(`${name} not found. Please install it first.`);
    return false;
  }
  return true;
}

function findWorkerHelper(snippetsDir) {
  for (const entry of readdirSync(snippetsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith("wasm-bindgen-rayon-")) {
      continue;
    }
    const workerHelperPath = join(snippetsDir, entry.name, "src/workerHelpers.js");
    if (existsSync(workerHelperPath)) {
      return workerHelperPath;
    }
  }

  throw new Error(`Could not find wasm-bindgen-rayon worker helper in ${snippetsDir}`);
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

  if (!checkCommand("nargo", "Noir (nargo)")) {
    log(
      "\nInstall Noir:\n  curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash"
    );
    log("  noirup --version v1.0.0-beta.19");
    process.exit(1);
  }
  logSuccess("nargo found");

  if (!checkCommand("cargo", "Rust (cargo)")) {
    log("\nInstall Rust: https://rustup.rs");
    process.exit(1);
  }
  logSuccess("cargo found");

  if (!checkCommand("wasm-bindgen", "wasm-bindgen CLI")) {
    log(
      "\nInstall wasm-bindgen CLI:\n  cargo install wasm-bindgen-cli --version 0.2.100"
    );
    process.exit(1);
  }
  logSuccess("wasm-bindgen found");

  logStep("2/5", "Installing browser dependencies...");
  if (!run("npm install --legacy-peer-deps", { cwd: DEMO_DIR })) {
    process.exit(1);
  }

  // Verity loads @noir-lang/* from node_modules directly; the old demo-local
  // vendor/pkg staging directories are no longer needed.
  for (const dir of ["vendor", "pkg", "pkg-web"]) {
    const fullPath = join(DEMO_DIR, dir);
    if (existsSync(fullPath)) {
      rmSync(fullPath, { recursive: true, force: true });
    }
  }
  logSuccess("Removed stale demo-local runtime asset directories");

  logStep("3/5", "Building local ProveKit WASM runtime...");
  if (!run("cargo build --release --target wasm32-unknown-unknown -p provekit-wasm -Z build-std=panic_abort,std", { cwd: ROOT_DIR })) {
    process.exit(1);
  }
  if (!run("wasm-bindgen --target web --out-dir tooling/provekit-wasm/pkg target/wasm32-unknown-unknown/release/provekit_wasm.wasm", { cwd: ROOT_DIR })) {
    process.exit(1);
  }

  const wasmPkgDir = join(ROOT_DIR, "tooling/provekit-wasm/pkg");
  const verityWasmDir = join(DEMO_DIR, "node_modules/@atheonxyz/verity/dist/wasm");
  for (const file of [
    "provekit_wasm.js",
    "provekit_wasm.d.ts",
    "provekit_wasm_bg.wasm",
    "provekit_wasm_bg.wasm.d.ts",
  ]) {
    copyFileSync(join(wasmPkgDir, file), join(verityWasmDir, file));
  }
  rmSync(join(verityWasmDir, "snippets"), { recursive: true, force: true });
  cpSync(join(wasmPkgDir, "snippets"), join(verityWasmDir, "snippets"), { recursive: true });
  const workerHelperPath = findWorkerHelper(join(verityWasmDir, "snippets"));
  const workerHelper = readFileSync(workerHelperPath, "utf-8");
  writeFileSync(
    workerHelperPath,
    workerHelper.replace("await import('../../..')", "await import('../../../../provekit_wasm.js')")
  );
  logSuccess("Demo runtime updated from local provekit-wasm build");

  // Build native CLI
  logStep("4/5", "Building native CLI...");
  if (!run("cargo build --profile release-fast --bin provekit-cli", { cwd: ROOT_DIR })) {
    process.exit(1);
  }
  logSuccess("Native CLI built");
}

async function prepareCircuit({ name, path: circuitDir }) {
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
  log(`\n📦 Preparing circuit: ${name} (${circuitName})`, colors.bright);
  log(`   Path: ${circuitDir}`);

  // Compile Noir circuit
  logStep(`${name}`, `Compiling Noir circuit (${circuitName})...`);
  if (!run("nargo compile", { cwd: circuitDir })) {
    process.exit(1);
  }
  logSuccess("Circuit compiled");

  // Copy compiled circuit
  const circuitSrc = join(circuitDir, `target/${circuitName}.json`);
  const circuitDest = join(artifactsDir, "circuit.json");
  if (!existsSync(circuitSrc)) {
    logError(`Compiled circuit not found: ${circuitSrc}`);
    process.exit(1);
  }
  copyFileSync(circuitSrc, circuitDest);
  logSuccess(`Circuit artifact copied (${circuitName}.json -> circuit.json)`);

  // Prepare prover/verifier artifacts
  logStep(`${name}`, "Preparing prover/verifier artifacts...");
  const cliPath = join(ROOT_DIR, "target/release-fast/provekit-cli");
  const proverBinPath = join(artifactsDir, "prover.pkp");
  const verifierBinPath = join(artifactsDir, "verifier.pkv");

  if (
    !run(
      `${cliPath} prepare ${circuitDir} --pkp ${proverBinPath} --pkv ${verifierBinPath} --hash blake3 --skip-brillig-constraints-check`,
      { cwd: artifactsDir }
    )
  ) {
    process.exit(1);
  }
  logSuccess("prover.pkp and verifier.pkv created");


  // Copy Prover.toml and convert to inputs.json
  logStep(`${name}`, "Preparing inputs...");
  const proverTomlSrc = join(circuitDir, "Prover.toml");
  const proverTomlDest = join(artifactsDir, "Prover.toml");
  copyFileSync(proverTomlSrc, proverTomlDest);
  logSuccess("Prover.toml copied");

  // Convert Prover.toml to inputs.json for browser demo
  const tomlContent = readFileSync(proverTomlSrc, "utf-8");
  const inputs = parseSimpleToml(tomlContent);
  const inputsJsonPath = join(artifactsDir, "inputs.json");
  writeFileSync(inputsJsonPath, JSON.stringify(inputs, null, 2));
  logSuccess("inputs.json created");

  // Save circuit metadata
  const metadataPath = join(artifactsDir, "metadata.json");
  writeFileSync(
    metadataPath,
    JSON.stringify(
      {
        name: circuitName,
        path: circuitDir,
      },
      null,
      2
    )
  );
  logSuccess("metadata.json created");
}

async function main() {
  await buildShared();

  logStep("5/5", `Preparing ${CIRCUITS.length} circuits...`);
  for (const circuit of CIRCUITS) {
    await prepareCircuit(circuit);
  }

  log("\n\u2705 Setup complete!\n", colors.green + colors.bright);
  log("Run the demo with:", colors.bright);
  log("  npm run serve            # Build and start the browser demo server");
  log("  # Open http://localhost:8080\n");
}

main().catch((err) => {
  logError(err.message);
  process.exit(1);
});
