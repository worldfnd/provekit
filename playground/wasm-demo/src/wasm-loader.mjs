/**
 * WASM module loader for Node.js.
 *
 * Handles loading the ProveKit WASM module in a Node.js environment.
 * Note: The WASM is built for 'web' target (required for wasm-bindgen-rayon threading),
 * so we need to polyfill browser globals and manually initialize it.
 * 
 * Threading is NOT available in Node.js - the prover runs single-threaded.
 */

import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { webcrypto } from "crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Polyfill Web Crypto API for WASM (used by getrandom/rand crates)
// Node.js has webcrypto but it's not exposed as globalThis.crypto by default
if (typeof globalThis.crypto === "undefined") {
  globalThis.crypto = webcrypto;
}

// Polyfill browser globals for wasm-bindgen-rayon compatibility
// These are needed because the WASM is built with 'web' target
// The workerHelpers.js expects these APIs but we stub them out for Node.js
if (typeof globalThis.self === "undefined") {
  globalThis.self = {
    // Stub addEventListener - workerHelpers.js calls this at import time
    // The promise will never resolve but that's fine (it's waiting for Worker messages)
    addEventListener: () => {},
    removeEventListener: () => {},
    postMessage: () => {},
    crypto: globalThis.crypto,
  };
}

// Also expose on globalThis for some contexts
if (typeof globalThis.addEventListener === "undefined") {
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
  globalThis.postMessage = () => {};
}

/**
 * Load and initialize the ProveKit WASM module.
 * @returns {Promise<Object>} The initialized WASM module exports
 */
export async function loadProveKitWasm() {
  const pkgDir = join(__dirname, "../pkg");

  // Check if WASM package exists
  const wasmPath = join(pkgDir, "provekit_wasm_bg.wasm");
  if (!existsSync(wasmPath)) {
    throw new Error(
      `WASM binary not found at ${wasmPath}. Run 'npm run setup' first.`
    );
  }

  // Import the web-targeted module (ESM)
  const wasmModule = await import("../pkg/provekit_wasm.js");

  // Read WASM binary and initialize manually (web target requires this)
  const wasmBytes = await readFile(wasmPath);
  await wasmModule.default(wasmBytes);

  // Initialize panic hook for better error messages
  if (wasmModule.initPanicHook) {
    wasmModule.initPanicHook();
  }

  // Note: Thread pool initialization is skipped for Node.js
  // wasm-bindgen-rayon uses Web Workers which don't work in Node.js
  // The prover will run single-threaded but still functional
  console.log("  ⚠️  Running in single-threaded mode (Node.js)");

  return wasmModule;
}
