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
  external: ["@noir-lang/acvm_js", "@noir-lang/noir_js"],
});
