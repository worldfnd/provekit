#!/usr/bin/env node

import { execSync, spawnSync } from "child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "fs";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, "../../..");
const DEMO_DIR = resolve(__dirname, "..");
const OUT_DIR = join(DEMO_DIR, "pkg-local");
const WASM_PATH = join(
  ROOT_DIR,
  "target/wasm32-unknown-unknown/release/provekit_wasm.wasm"
);
const BG_WASM_PATH = join(OUT_DIR, "provekit_wasm_bg.wasm");

function run(cmd, opts = {}) {
  console.log(`  $ ${cmd}`);
  execSync(cmd, { stdio: "inherit", ...opts });
}

function commandExists(cmd) {
  return spawnSync("which", [cmd], { stdio: "ignore" }).status === 0;
}

function patchRayonWorkerImport() {
  const snippetsDir = join(OUT_DIR, "snippets");
  if (!existsSync(snippetsDir)) {
    return;
  }

  for (const name of readdirSync(snippetsDir)) {
    if (!name.startsWith("wasm-bindgen-rayon-")) {
      continue;
    }

    const workerPath = join(snippetsDir, name, "src/workerHelpers.js");
    if (!existsSync(workerPath)) {
      continue;
    }

    const source = readFileSync(workerPath, "utf8");
    const patched = source
      .replace("await import('../../..')", "await import('../../../provekit_wasm.js')")
      .replace('await import("../../..")', 'await import("../../../provekit_wasm.js")');

    if (patched !== source) {
      writeFileSync(workerPath, patched);
    }
  }
}

function main() {
  if (!commandExists("wasm-bindgen")) {
    throw new Error(
      "wasm-bindgen not found. Install it with: cargo install wasm-bindgen-cli --version 0.2.100"
    );
  }

  rmSync(OUT_DIR, { recursive: true, force: true });
  mkdirSync(OUT_DIR, { recursive: true });

  run(
    "cargo +nightly-2026-03-04 build -p provekit-wasm --release --target wasm32-unknown-unknown -Z build-std=panic_abort,std",
    { cwd: ROOT_DIR }
  );
  run(`wasm-bindgen --target web --out-dir ${OUT_DIR} ${WASM_PATH}`, {
    cwd: ROOT_DIR,
  });

  patchRayonWorkerImport();

  if (commandExists("wasm-opt")) {
    run(
      `wasm-opt -O3 --enable-simd --enable-threads --enable-bulk-memory --enable-mutable-globals --enable-nontrapping-float-to-int --enable-sign-ext --fast-math --low-memory-unused -o ${BG_WASM_PATH} ${BG_WASM_PATH}`,
      { cwd: ROOT_DIR }
    );
  } else {
    console.warn("wasm-opt not found; leaving provekit_wasm_bg.wasm unoptimized");
  }
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
