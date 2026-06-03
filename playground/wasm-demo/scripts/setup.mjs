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
import { createHash } from "crypto";
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
const MAVROS_REV = "cab81e6318d88a988e6937e2d923b77c096b1f4f";
const DEFAULT_V1_DIR = resolve(ROOT_DIR, "../provekit-v1-passkey-webauthn");
const V1_DIR = process.env.PROVEKIT_V1_DIR ? resolve(process.env.PROVEKIT_V1_DIR) : DEFAULT_V1_DIR;
const CIRCUITS = [
  { name: "passkey", relativePath: "noir-examples/passkey_p256", path: join(ROOT_DIR, "noir-examples/passkey_p256") },
  { name: "webauthn", relativePath: "playground/noir-webauthn-demo", path: join(ROOT_DIR, "playground/noir-webauthn-demo") },
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

function writeInputsAndMetadata({ artifactsDir, circuitDir, circuitName, backend, label, extraInputs = {} }) {
  const proverTomlSrc = join(circuitDir, "Prover.toml");
  const proverTomlDest = join(artifactsDir, "Prover.toml");
  copyFileSync(proverTomlSrc, proverTomlDest);
  logSuccess("Prover.toml copied");

  const tomlContent = readFileSync(proverTomlSrc, "utf-8");
  const inputs = { ...parseSimpleToml(tomlContent), ...extraInputs };
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

function copyFirstExisting(candidates, destination) {
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      copyFileSync(candidate, destination);
      return candidate;
    }
  }
  return null;
}

const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const TWO_POW_120 = 1n << 120n;
const P256_SCALAR_SLICES = 65;

function sha256Bytes(bytes) {
  return Array.from(createHash("sha256").update(Buffer.from(bytes)).digest());
}

function bytesToBigInt(bytes) {
  return bytes.reduce((acc, byte) => (acc << 8n) + BigInt(byte), 0n);
}

function modInverse(value, modulus) {
  let a = ((value % modulus) + modulus) % modulus;
  let b = modulus;
  let x0 = 1n;
  let x1 = 0n;

  while (b !== 0n) {
    const q = a / b;
    [a, b] = [b, a - q * b];
    [x0, x1] = [x1, x0 - q * x1];
  }

  if (a !== 1n) {
    throw new Error("P-256 scalar inverse does not exist");
  }
  return ((x0 % modulus) + modulus) % modulus;
}

function bytesToLimbs(bytes) {
  if (bytes.length !== 32) {
    throw new Error(`expected 32 bytes, got ${bytes.length}`);
  }
  return [
    bytesToBigInt(bytes.slice(17, 32)).toString(),
    bytesToBigInt(bytes.slice(2, 17)).toString(),
    bytesToBigInt(bytes.slice(0, 2)).toString(),
  ];
}

function littleEndian120BitNibbles(limb) {
  const nibbles = [];
  for (let byteIndex = 0n; nibbles.length < 30; byteIndex += 1n) {
    const byte = Number((limb >> (8n * byteIndex)) & 0xffn);
    nibbles.push(byte & 0x0f);
    if (nibbles.length < 30) {
      nibbles.push(byte >> 4);
    }
  }
  return nibbles;
}

function scalarToLimbs(value) {
  let remaining = ((value % P256_ORDER) + P256_ORDER) % P256_ORDER;
  const limbs = [];
  for (let i = 0; i < 3; i += 1) {
    limbs.push(remaining & (TWO_POW_120 - 1n));
    remaining >>= 120n;
  }
  return limbs;
}

function scalarToWnaf(value) {
  const limbs = scalarToLimbs(value);
  const nibbles = limbs.map(littleEndian120BitNibbles);
  const base4Slices = Array(P256_SCALAR_SLICES).fill(0);
  const skew = (nibbles[0][0] & 1) === 0;
  nibbles[0][0] += skew ? 1 : 0;
  base4Slices[P256_SCALAR_SLICES - 1] = Math.floor((nibbles[0][0] + 15) / 2);

  for (let i = 1; i < P256_SCALAR_SLICES; i += 1) {
    const majorIndex = Math.floor(i / 30);
    const minorIndex = i % 30;
    const nibble = nibbles[majorIndex][minorIndex];
    base4Slices[P256_SCALAR_SLICES - 1 - i] = Math.floor((nibble + 15) / 2);
    if ((nibble & 1) === 0) {
      base4Slices[P256_SCALAR_SLICES - 1 - i] += 1;
      base4Slices[P256_SCALAR_SLICES - i] -= 8;
    }
  }

  if (base4Slices.some((slice) => slice < 0 || slice > 15)) {
    throw new Error(`invalid P-256 scalar slice set: ${base4Slices.join(",")}`);
  }

  const high = signedSliceAccumulator(base4Slices.slice(0, 5));
  const mid = signedSliceAccumulator(base4Slices.slice(5, 35));
  const low = signedSliceAccumulator(base4Slices.slice(35, 65));

  return {
    slices: base4Slices,
    skew,
    borrow_mid: mid < 0n,
    borrow_low: low < 0n,
    debug: { high, mid, low },
  };
}

function signedSliceAccumulator(slices) {
  return slices.reduce((acc, slice) => acc * 16n + BigInt(slice) * 2n - 15n, 0n);
}

function boundedVecBytes(value) {
  return value.storage.slice(0, Number(value.len));
}

function p256AuxiliaryInputs(inputs, digestBytes, keyPrefix) {
  const signature = inputs.signature;
  const rBytes = signature.slice(0, 32);
  const sBytes = signature.slice(32, 64);
  const sInv = modInverse(bytesToBigInt(sBytes), P256_ORDER);
  const sG = (bytesToBigInt(digestBytes) * sInv) % P256_ORDER;
  const sP = (bytesToBigInt(rBytes) * sInv) % P256_ORDER;
  const sGWnaf = scalarToWnaf(sG);
  const sPWnaf = scalarToWnaf(sP);

  const publicKeyXLimbKey = `${keyPrefix}_x_limbs`;
  const publicKeyYLimbKey = `${keyPrefix}_y_limbs`;
  return {
    message_limbs: bytesToLimbs(digestBytes),
    [publicKeyXLimbKey]: bytesToLimbs(inputs[keyPrefix === "pub_key" ? "pub_key_x" : "public_key_x"]),
    [publicKeyYLimbKey]: bytesToLimbs(inputs[keyPrefix === "pub_key" ? "pub_key_y" : "public_key_y"]),
    signature_r_limbs: bytesToLimbs(rBytes),
    signature_s_limbs: bytesToLimbs(sBytes),
    r_point_y_limbs: bytesToLimbs(inputs.r_point_y),
    s_g_limbs: scalarToLimbs(sG).map((limb) => limb.toString()),
    s_g_slices: sGWnaf.slices,
    s_g_skew: sGWnaf.skew,
    s_g_borrow_low: sGWnaf.borrow_low,
    s_g_borrow_mid: sGWnaf.borrow_mid,
    s_p_limbs: scalarToLimbs(sP).map((limb) => limb.toString()),
    s_p_slices: sPWnaf.slices,
    s_p_skew: sPWnaf.skew,
    s_p_borrow_low: sPWnaf.borrow_low,
    s_p_borrow_mid: sPWnaf.borrow_mid,
  };
}

function mavrosExtraInputs(name, inputs) {
  if (name === "passkey") {
    const digest = sha256Bytes([...inputs.authenticator_data, ...inputs.challenge_commitment]);
    return p256AuxiliaryInputs(inputs, digest, "pub_key");
  }

  if (name === "webauthn") {
    const clientHash = sha256Bytes(boundedVecBytes(inputs.client_data_json));
    const digest = sha256Bytes([...boundedVecBytes(inputs.authenticator_data), ...clientHash]);
    return p256AuxiliaryInputs(inputs, digest, "public_key");
  }

  return {};
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
    label: "Patched branch ACIR",
    extraInputs: mavrosExtraInputs(name, parseSimpleToml(readFileSync(join(circuitDir, "Prover.toml"), "utf-8"))),
  });
  writeBackendStatus(artifactsDir, {
    available: true,
    backend: "acir",
    label: "Patched branch ACIR",
  });
}

async function prepareV1Circuit({ name, relativePath }) {
  const artifactsDir = join(DEMO_DIR, "artifacts", `${name}-v1`);
  rmSync(artifactsDir, { recursive: true, force: true });
  mkdirSync(artifactsDir, { recursive: true });

  const circuitDir = join(V1_DIR, relativePath);
  const sourceArtifactsDir = join(circuitDir, "artifacts");
  const proverSrc = join(sourceArtifactsDir, "prover.pkp");
  const verifierSrc = join(sourceArtifactsDir, "verifier.pkv");

  log(`\n📦 Preparing ProveKit v1 ACIR circuit: ${name}`, colors.bright);
  log(`   v1 path: ${circuitDir}`);

  if (!existsSync(circuitDir) || !existsSync(proverSrc) || !existsSync(verifierSrc)) {
    const error = `ProveKit v1 artifacts not found. Expected ${proverSrc} and ${verifierSrc}. Set PROVEKIT_V1_DIR to the v1 worktree.`;
    logError(error);
    writeBackendStatus(artifactsDir, {
      available: false,
      backend: "verity-v1",
      label: "ProveKit v1 ACIR (Verity WASM)",
      error,
    });
    return;
  }

  const circuitName = getCircuitName(circuitDir);
  copyFileSync(proverSrc, join(artifactsDir, "prover.pkp"));
  copyFileSync(verifierSrc, join(artifactsDir, "verifier.pkv"));
  logSuccess("v1 prover.pkp and verifier.pkv copied");

  logStep(`${name}-v1`, "Preparing inputs...");
  writeInputsAndMetadata({
    artifactsDir,
    circuitDir,
    circuitName,
    backend: "verity-v1",
    label: "ProveKit v1 ACIR (Verity WASM)",
  });
  writeBackendStatus(artifactsDir, {
    available: true,
    backend: "verity-v1",
    label: "ProveKit v1 ACIR (Verity WASM)",
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
    extraInputs: mavrosExtraInputs(name, parseSimpleToml(readFileSync(join(circuitDir, "Prover.toml"), "utf-8"))),
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

  logStep(`${name}-mavros`, "Emitting Mavros browser WASM modules...");
  const emitResult = runArgs([
    ...mavrosCommand,
    "--root", circuitDir,
    "--emit-wasm",
    "--skip-vm",
  ], { cwd: artifactsDir });
  if (!emitResult.ok) {
    const error = `Mavros WASM emit failed: ${truncateOutput(emitResult.output)}`;
    logError(error);
    writeBackendStatus(artifactsDir, {
      available: false,
      backend: "mavros",
      label: "Mavros main",
      error,
    });
    return;
  }

  const witgenSource = copyFirstExisting([
    join(circuitDir, "mavros_debug", "witgen.wasm"),
    join(artifactsDir, "mavros_debug", "witgen.wasm"),
    join(mavrosDir, "mavros_debug", "witgen.wasm"),
  ], join(artifactsDir, "witgen.wasm"));
  if (witgenSource) {
    logSuccess(`witgen.wasm copied from ${witgenSource}`);
    copyFirstExisting([
      `${witgenSource}.meta.json`,
      join(circuitDir, "mavros_debug", "witgen.wasm.meta.json"),
      join(artifactsDir, "mavros_debug", "witgen.wasm.meta.json"),
      join(mavrosDir, "mavros_debug", "witgen.wasm.meta.json"),
    ], join(artifactsDir, "witgen.wasm.meta.json"));
  }

  const adSource = copyFirstExisting([
    join(circuitDir, "mavros_debug", "ad.wasm"),
    join(artifactsDir, "mavros_debug", "ad.wasm"),
    join(mavrosDir, "mavros_debug", "ad.wasm"),
  ], join(artifactsDir, "ad.wasm"));
  if (adSource) {
    logSuccess(`ad.wasm copied from ${adSource}`);
    copyFirstExisting([
      `${adSource}.meta.json`,
      join(circuitDir, "mavros_debug", "ad.wasm.meta.json"),
      join(artifactsDir, "mavros_debug", "ad.wasm.meta.json"),
      join(mavrosDir, "mavros_debug", "ad.wasm.meta.json"),
    ], join(artifactsDir, "ad.wasm.meta.json"));
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

  if (!witgenSource || !adSource) {
    const missing = [
      !witgenSource ? "witgen.wasm" : null,
      !adSource ? "ad.wasm" : null,
    ].filter(Boolean).join(" and ");
    writeBackendStatus(artifactsDir, {
      available: false,
      backend: "mavros",
      label: "Mavros main",
      error: `Mavros prover artifacts were prepared, but ${missing} was not emitted by Mavros main at ${MAVROS_REV}.`,
    });
    return;
  }

  writeBackendStatus(artifactsDir, {
    available: true,
    backend: "mavros",
    label: "Mavros main",
  });
}

async function main() {
  await buildShared();

  logStep("5/5", `Preparing ${CIRCUITS.length} circuits and comparison backends...`);
  for (const circuit of CIRCUITS) {
    await prepareAcirCircuit(circuit);
    await prepareMavrosCircuit(circuit);
    await prepareV1Circuit(circuit);
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
