import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  platform: "neutral",
  target: "es2022",
  dts: true,
  clean: false,
  splitting: false,
  sourcemap: true,
  external: [
    "@noir-lang/acvm_js",
    "@noir-lang/acvm_js/web/acvm_js_bg.wasm?url",
    "@noir-lang/noir_js",
    "@noir-lang/noirc_abi",
    "@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url",
    "./wasm/single/provekit_wasm.js",
    "./wasm/single/provekit_wasm_bg.wasm?url",
    "./wasm/threaded/provekit_wasm.js",
    "./wasm/threaded/provekit_wasm_bg.wasm?url",
  ],
});
