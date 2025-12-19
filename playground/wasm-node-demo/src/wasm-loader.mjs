/**
 * WASM module loader for Node.js.
 *
 * Handles loading the ProveKit WASM module in a Node.js environment.
 */

import { existsSync } from "fs";
import { createRequire } from "module";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

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

  // Load the CommonJS module using require
  // The nodejs target auto-initializes the WASM module
  const wasmModule = require("../pkg/provekit_wasm.js");

  // Initialize panic hook for better error messages
  if (wasmModule.initPanicHook) {
    wasmModule.initPanicHook();
  }

  return wasmModule;
}
