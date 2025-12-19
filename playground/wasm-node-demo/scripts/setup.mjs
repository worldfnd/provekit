#!/usr/bin/env node
/**
 * Setup script for ProveKit WASM browser demo.
 *
 * Usage:
 *   node scripts/setup.mjs [circuit-path]
 *
 * Arguments:
 *   circuit-path  Path to Noir circuit directory (default: noir-examples/oprf)
 *
 * This script builds all required artifacts:
 * 1. WASM package with thread support (via build-wasm.sh)
 * 2. Noir circuit (via nargo)
 * 3. Prover/Verifier binary artifacts (via provekit-cli)
 */

import { execSync, spawnSync } from "child_process";
import {
  existsSync,
  mkdirSync,
  copyFileSync,
  readFileSync,
  writeFileSync,
  readdirSync,
} from "fs";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, "../../..");
const DEMO_DIR = resolve(__dirname, "..");
const ARTIFACTS_DIR = join(DEMO_DIR, "artifacts");
const WASM_PKG_DIR = join(ROOT_DIR, "tooling/provekit-wasm/pkg");

// Parse command line arguments (filter out "--" which npm/pnpm passes)
const args = process.argv.slice(2).filter((arg) => arg !== "--");
let circuitPath = args[0];

// Default to oprf if no argument provided
if (!circuitPath) {
  circuitPath = join(ROOT_DIR, "noir-examples/oprf");
} else {
  // Resolve relative paths
  circuitPath = resolve(process.cwd(), circuitPath);
}

const CIRCUIT_DIR = circuitPath;

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

/**
 * Parse a TOML value (handles strings, arrays, inline tables)
 */
function parseTomlValue(valueStr) {
  valueStr = valueStr.trim();

  // String
  if (valueStr.startsWith('"') && valueStr.endsWith('"')) {
    return valueStr.slice(1, -1);
  }

  // Inline table { key = "value", ... }
  if (valueStr.startsWith("{") && valueStr.endsWith("}")) {
    const inner = valueStr.slice(1, -1).trim();
    const obj = {};
    // Parse key = value pairs, handling nested structures
    let depth = 0;
    let currentKey = "";
    let currentValue = "";
    let inKey = true;
    let inString = false;

    for (let i = 0; i < inner.length; i++) {
      const char = inner[i];

      if (char === '"' && inner[i - 1] !== "\\") {
        inString = !inString;
      }

      if (!inString) {
        if (char === "{" || char === "[") depth++;
        if (char === "}" || char === "]") depth--;

        if (char === "=" && depth === 0 && inKey) {
          inKey = false;
          continue;
        }

        if (char === "," && depth === 0) {
          if (currentKey.trim() && currentValue.trim()) {
            obj[currentKey.trim()] = parseTomlValue(currentValue.trim());
          }
          currentKey = "";
          currentValue = "";
          inKey = true;
          continue;
        }
      }

      if (inKey) {
        currentKey += char;
      } else {
        currentValue += char;
      }
    }

    // Handle last key-value pair
    if (currentKey.trim() && currentValue.trim()) {
      obj[currentKey.trim()] = parseTomlValue(currentValue.trim());
    }

    return obj;
  }

  // Array [ ... ]
  if (valueStr.startsWith("[") && valueStr.endsWith("]")) {
    const inner = valueStr.slice(1, -1).trim();
    if (!inner) return [];

    const items = [];
    let depth = 0;
    let current = "";
    let inString = false;

    for (let i = 0; i < inner.length; i++) {
      const char = inner[i];

      if (char === '"' && inner[i - 1] !== "\\") {
        inString = !inString;
      }

      if (!inString) {
        if (char === "{" || char === "[") depth++;
        if (char === "}" || char === "]") depth--;

        if (char === "," && depth === 0) {
          if (current.trim()) {
            items.push(parseTomlValue(current.trim()));
          }
          current = "";
          continue;
        }
      }

      current += char;
    }

    if (current.trim()) {
      items.push(parseTomlValue(current.trim()));
    }

    return items;
  }

  // Number or bare string
  return valueStr;
}

/**
 * Check if brackets are balanced in a string
 */
function areBracketsBalanced(str) {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (char === '"' && str[i - 1] !== "\\") {
      inString = !inString;
    }
    if (!inString) {
      if (char === "[" || char === "{") depth++;
      if (char === "]" || char === "}") depth--;
    }
  }
  return depth === 0;
}

/**
 * Parse Prover.toml to JSON for browser demo
 */
function parseProverToml(content) {
  const result = {};
  const lines = content.split("\n");
  let currentSection = null;
  let pendingLine = "";

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();

    // Skip comments and empty lines (unless we're accumulating a multi-line value)
    if (!pendingLine && (!line || line.startsWith("#"))) continue;

    // If we have a pending line, append this line to it
    if (pendingLine) {
      // Skip comment lines within multi-line values
      if (line.startsWith("#")) continue;
      pendingLine += " " + line;
      line = pendingLine;

      // Check if brackets are balanced now
      if (!areBracketsBalanced(line)) {
        continue; // Keep accumulating
      }
      pendingLine = "";
    }

    // Section header [section]
    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1];
      continue;
    }

    // Key = value (find first = that's not inside a string or nested structure)
    const eqIndex = findTopLevelEquals(line);
    if (eqIndex !== -1) {
      const key = line.slice(0, eqIndex).trim();
      const valueStr = line.slice(eqIndex + 1).trim();

      // Check if this is an incomplete multi-line value
      if (!areBracketsBalanced(valueStr)) {
        pendingLine = line;
        continue;
      }

      const value = parseTomlValue(valueStr);

      const fullKey = currentSection ? `${currentSection}.${key}` : key;
      setNestedValue(result, fullKey, value);
    }
  }

  return result;
}

/**
 * Find the first = that's not inside quotes or nested structures
 */
function findTopLevelEquals(line) {
  let inString = false;
  let depth = 0;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (char === '"' && line[i - 1] !== "\\") {
      inString = !inString;
    }

    if (!inString) {
      if (char === "{" || char === "[") depth++;
      if (char === "}" || char === "]") depth--;
      if (char === "=" && depth === 0) {
        return i;
      }
    }
  }

  return -1;
}

function setNestedValue(obj, path, value) {
  const parts = path.split(".");
  let current = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!(parts[i] in current)) {
      current[parts[i]] = {};
    }
    current = current[parts[i]];
  }
  current[parts[parts.length - 1]] = value;
}

async function main() {
  log("\n🔧 ProveKit WASM Demo Setup\n", colors.bright);

  // Validate circuit directory
  if (!existsSync(CIRCUIT_DIR)) {
    logError(`Circuit directory not found: ${CIRCUIT_DIR}`);
    process.exit(1);
  }

  const circuitName = getCircuitName(CIRCUIT_DIR);
  log(`Circuit: ${circuitName}`, colors.bright);
  log(`Path: ${CIRCUIT_DIR}\n`);

  // Check prerequisites
  logStep("1/6", "Checking prerequisites...");

  if (!checkCommand("nargo", "Noir (nargo)")) {
    log(
      "\nInstall Noir:\n  curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash"
    );
    log("  noirup --version v1.0.0-beta.11");
    process.exit(1);
  }
  logSuccess("nargo found");

  if (!checkCommand("wasm-pack", "wasm-pack")) {
    log("\nInstall wasm-pack:\n  cargo install wasm-pack");
    process.exit(1);
  }
  logSuccess("wasm-pack found");

  if (!checkCommand("cargo", "Rust (cargo)")) {
    log("\nInstall Rust: https://rustup.rs");
    process.exit(1);
  }
  logSuccess("cargo found");

  // Create artifacts directory
  if (!existsSync(ARTIFACTS_DIR)) {
    mkdirSync(ARTIFACTS_DIR, { recursive: true });
  }

  // Build WASM package with thread support (atomics enabled)
  logStep("2/6", "Building WASM package with thread support...");

  // Use the build-wasm.sh script which enables atomics for wasm-bindgen-rayon
  const buildScript = join(ROOT_DIR, "tooling/provekit-wasm/build-wasm.sh");
  if (existsSync(buildScript)) {
    if (!run(`bash ${buildScript} web`, { cwd: ROOT_DIR })) {
      // Fallback: try building without thread support
      log(
        "  Warning: Thread-enabled build failed, trying without atomics...",
        colors.yellow
      );
      if (
        !run(`wasm-pack build tooling/provekit-wasm --release --target web`, {
          cwd: ROOT_DIR,
        })
      ) {
        process.exit(1);
      }
    }
  } else {
    // Fallback to wasm-pack if build script doesn't exist
    if (
      !run(`wasm-pack build tooling/provekit-wasm --release --target web`, {
        cwd: ROOT_DIR,
      })
    ) {
      process.exit(1);
    }
  }
  logSuccess("WASM package built");

  // Copy WASM package to demo/pkg
  const wasmDestDir = join(DEMO_DIR, "pkg");
  if (!existsSync(wasmDestDir)) {
    mkdirSync(wasmDestDir, { recursive: true });
  }

  for (const file of [
    "provekit_wasm_bg.wasm",
    "provekit_wasm.js",
    "provekit_wasm.d.ts",
    "package.json",
  ]) {
    const src = join(WASM_PKG_DIR, file);
    const dest = join(wasmDestDir, file);
    if (existsSync(src)) {
      copyFileSync(src, dest);
    }
  }

  // Copy snippets directory (for wasm-bindgen-rayon worker helpers)
  const snippetsDir = join(WASM_PKG_DIR, "snippets");
  if (existsSync(snippetsDir)) {
    const snippetsDestDir = join(wasmDestDir, "snippets");
    if (!existsSync(snippetsDestDir)) {
      mkdirSync(snippetsDestDir, { recursive: true });
    }
    // Recursively copy snippets
    function copyDirRecursive(src, dest) {
      if (!existsSync(dest)) mkdirSync(dest, { recursive: true });
      for (const entry of readdirSync(src, { withFileTypes: true })) {
        const srcPath = join(src, entry.name);
        const destPath = join(dest, entry.name);
        if (entry.isDirectory()) {
          copyDirRecursive(srcPath, destPath);
        } else {
          copyFileSync(srcPath, destPath);
        }
      }
    }
    copyDirRecursive(snippetsDir, snippetsDestDir);
    logSuccess("WASM snippets copied (for thread pool)");

    // Patch workerHelpers.js to fix the import path for browser
    // The default '../../..' resolves to directory, not the JS file
    function patchWorkerHelpers(dir) {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          patchWorkerHelpers(fullPath);
        } else if (entry.name === "workerHelpers.js") {
          let content = readFileSync(fullPath, "utf-8");
          content = content.replace(
            "import('../../..')",
            "import('../../../provekit_wasm.js')"
          );
          writeFileSync(fullPath, content);
        }
      }
    }
    patchWorkerHelpers(snippetsDestDir);
    logSuccess("Worker helpers patched for browser imports");
  }
  logSuccess("WASM package copied to demo/pkg");

  // Compile Noir circuit
  logStep("3/6", `Compiling Noir circuit (${circuitName})...`);
  if (!run("nargo compile", { cwd: CIRCUIT_DIR })) {
    process.exit(1);
  }
  logSuccess("Circuit compiled");

  // Copy compiled circuit
  const circuitSrc = join(CIRCUIT_DIR, `target/${circuitName}.json`);
  const circuitDest = join(ARTIFACTS_DIR, "circuit.json");
  if (!existsSync(circuitSrc)) {
    logError(`Compiled circuit not found: ${circuitSrc}`);
    process.exit(1);
  }
  copyFileSync(circuitSrc, circuitDest);
  logSuccess(`Circuit artifact copied (${circuitName}.json -> circuit.json)`);

  // Build native CLI (for verification)
  logStep("4/6", "Building native CLI...");
  if (!run("cargo build --release --bin provekit-cli", { cwd: ROOT_DIR })) {
    process.exit(1);
  }
  logSuccess("Native CLI built");

  // Prepare prover/verifier artifacts (binary format)
  logStep("5/6", "Preparing prover/verifier artifacts...");
  const cliPath = join(ROOT_DIR, "target/release/provekit-cli");
  const proverBinPath = join(ARTIFACTS_DIR, "prover.pkp");
  const verifierBinPath = join(ARTIFACTS_DIR, "verifier.pkv");

  if (
    !run(
      `${cliPath} prepare ${circuitDest} --pkp ${proverBinPath} --pkv ${verifierBinPath}`,
      { cwd: ARTIFACTS_DIR }
    )
  ) {
    process.exit(1);
  }
  logSuccess("prover.pkp and verifier.pkv created");

  // Copy Prover.toml and convert to inputs.json
  logStep("6/6", "Preparing inputs...");
  const proverTomlSrc = join(CIRCUIT_DIR, "Prover.toml");
  const proverTomlDest = join(ARTIFACTS_DIR, "Prover.toml");
  copyFileSync(proverTomlSrc, proverTomlDest);
  logSuccess("Prover.toml copied");

  // Convert Prover.toml to inputs.json for browser demo
  const tomlContent = readFileSync(proverTomlSrc, "utf-8");
  const inputs = parseProverToml(tomlContent);
  const inputsJsonPath = join(ARTIFACTS_DIR, "inputs.json");
  writeFileSync(inputsJsonPath, JSON.stringify(inputs, null, 2));
  logSuccess("inputs.json created (for browser demo)");

  // Save circuit metadata (name, path) for demo
  const metadataPath = join(ARTIFACTS_DIR, "metadata.json");
  writeFileSync(
    metadataPath,
    JSON.stringify({ name: circuitName, path: CIRCUIT_DIR }, null, 2)
  );
  logSuccess("metadata.json created");

  log("\n✅ Setup complete!\n", colors.green + colors.bright);
  log("Run the demo with:", colors.bright);
  log("  node scripts/serve.mjs    # Start browser demo server");
  log("  # Open http://localhost:8080\n");
}

main().catch((err) => {
  logError(err.message);
  process.exit(1);
});
