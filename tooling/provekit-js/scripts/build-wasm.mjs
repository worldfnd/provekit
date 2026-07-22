import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const outputDir = resolve(repositoryRoot, "tooling/provekit-wasm/pkg");
const lock = readFileSync(resolve(repositoryRoot, "Cargo.lock"), "utf8");
const version = /\[\[package\]\]\nname = "wasm-bindgen"\nversion = "([^"]+)"/.exec(lock)?.[1];
if (!version) throw new Error("Could not derive wasm-bindgen version from Cargo.lock");

function run(command, args, options = {}) {
  execFileSync(command, args, { cwd: repositoryRoot, stdio: "inherit", ...options });
}

run("cargo", ["install", "wasm-bindgen-cli", "--version", version, "--locked"]);

await rm(outputDir, { recursive: true, force: true });
await mkdir(outputDir, { recursive: true });

function buildVariant(variant, threaded) {
  const targetDir = resolve(repositoryRoot, `target/provekit-js-wasm-${variant}`);
  const variantOutput = resolve(outputDir, variant);
  const cargoArgs = [
    "build",
    "--release",
    "--target",
    "wasm32-unknown-unknown",
    "-p",
    "provekit-wasm",
    "--target-dir",
    targetDir,
    "-Z",
    "build-std=panic_abort,std",
  ];
  if (!threaded) cargoArgs.push("--no-default-features");
  const options = threaded
    ? {}
    : {
        env: {
          ...process.env,
          RUSTFLAGS: "-C target-feature=+simd128,+relaxed-simd",
        },
      };
  run("cargo", cargoArgs, options);
  run("wasm-bindgen", [
    "--target",
    "web",
    "--out-dir",
    variantOutput,
    resolve(targetDir, "wasm32-unknown-unknown/release/provekit_wasm.wasm"),
  ]);

  const wasm = resolve(variantOutput, "provekit_wasm_bg.wasm");
  const wasmOptArgs = [
    "-O3",
    "--enable-simd",
    "--enable-bulk-memory",
    "--enable-mutable-globals",
    "--enable-nontrapping-float-to-int",
    "--enable-sign-ext",
    "--fast-math",
    "--low-memory-unused",
  ];
  if (threaded) wasmOptArgs.push("--enable-threads");
  wasmOptArgs.push("-o", wasm, wasm);
  run("wasm-opt", wasmOptArgs);
}

buildVariant("threaded", true);
buildVariant("single", false);
