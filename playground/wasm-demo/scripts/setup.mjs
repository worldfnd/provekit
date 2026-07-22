#!/usr/bin/env node
/**
 * Setup script for the ProveKit browser demo.
 *
 * Usage:
 *   node scripts/setup.mjs
 *
 * Installs browser dependencies, builds the native CLI once, then prepares
 * both SHA256 and Poseidon circuits
 * into artifacts/sha256/ and artifacts/poseidon/ respectively.
 */

import { execSync, spawnSync } from "child_process";
import {
  existsSync,
  mkdirSync,
  rmSync,
  copyFileSync,
  readFileSync,
  writeFileSync,
} from "fs";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";
import { parseSimpleToml } from "../shared/toml-parser.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, "../../..");
const DEMO_DIR = resolve(__dirname, "..");
const SDK_DIR = join(ROOT_DIR, "tooling/provekit-js");
const CIRCUITS = [
  { name: "sha256",   path: join(ROOT_DIR, "noir-examples/noir_sha256") },
  { name: "poseidon", path: join(ROOT_DIR, "noir-examples/poseidon-rounds") },
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
  logStep("1/4", "Checking prerequisites...");

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

  logStep("2/4", "Installing browser dependencies...");
  if (!run("npm ci", { cwd: SDK_DIR })) {
    process.exit(1);
  }
  if (!run("npm run build:wasm", { cwd: SDK_DIR })) {
    process.exit(1);
  }
  if (!run("npm run build", { cwd: SDK_DIR })) {
    process.exit(1);
  }
  if (!run("npm install --legacy-peer-deps", { cwd: DEMO_DIR })) {
    process.exit(1);
  }
  if (!run("node scripts/install-packed-sdk.mjs", { cwd: DEMO_DIR })) {
    process.exit(1);
  }

  // @worldcoin/provekit loads @noir-lang/* from node_modules directly; the old demo-local
  // vendor/pkg staging directories are no longer needed.
  for (const dir of ["vendor", "pkg", "pkg-web"]) {
    const fullPath = join(DEMO_DIR, dir);
    if (existsSync(fullPath)) {
      rmSync(fullPath, { recursive: true, force: true });
    }
  }
  logSuccess("Removed stale demo-local runtime asset directories");

  // Build native CLI
  logStep("3/4", "Building native CLI...");
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
      `${cliPath} prepare ${circuitDir} --force --pkp ${proverBinPath} --pkv ${verifierBinPath} --hash blake3`,
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

  logStep("4/4", `Preparing ${CIRCUITS.length} circuits...`);
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
