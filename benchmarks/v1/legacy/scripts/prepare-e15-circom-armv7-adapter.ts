#!/usr/bin/env bun

import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";

const [templateArg, outputArg] = process.argv.slice(2);
if (!templateArg || !outputArg) {
  throw new Error(
    "usage: bun prepare-e15-circom-armv7-adapter.ts <configured-mopro-project> <output-project>",
  );
}

const template = resolve(templateArg);
const output = resolve(outputArg);
const moduleSource = resolve(
  import.meta.dir,
  "../mopro/e15_circom_frozen_mobench.rs",
);
for (const required of [
  join(template, "Cargo.toml"),
  join(template, "src/error.rs"),
  join(template, "src/stubs.rs"),
  moduleSource,
]) {
  if (!existsSync(required))
    throw new Error(`required path does not exist: ${required}`);
}

rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
for (const relative of ["src/error.rs", "src/stubs.rs"]) {
  const destination = join(output, relative);
  mkdirSync(dirname(destination), { recursive: true });
  cpSync(join(template, relative), destination);
}

let cargo = readFileSync(join(template, "Cargo.toml"), "utf8");
cargo = cargo.replace(
  /\nnoir_rs = \{ package = "noir",[\s\S]*?tag = "v1\.0\.0-beta\.19" \}\s*/,
  "\n",
);
cargo = cargo.replace(/\nserial_test = "[^"]+"\s*/g, "\n");
cargo = cargo.replace(/\nwitnesscalc-adapter = "[^"]+"\s*/g, "\n");
cargo = cargo.replace(/\nrust-witness = "[^"]+"\s*/g, "\n");
cargo = cargo.replace(/\ncc = "[^"]+"\s*/g, "\n");
if (!cargo.includes('num-bigint    = "0.4.0"')) {
  throw new Error(
    "configured template is missing the pinned num-bigint dependency",
  );
}
writeFileSync(join(output, "Cargo.toml"), cargo);
writeFileSync(join(output, "build.rs"), "fn main() {}\n");
cpSync(moduleSource, join(output, "src/e15_circom_frozen_mobench.rs"));
writeFileSync(
  join(output, "src/lib.rs"),
  `#[macro_use]
mod stubs;

mod error;
pub use error::MoproError;

#[cfg(not(target_arch = "wasm32"))]
mopro_ffi::app!();

mod e15_circom_frozen_mobench;
use e15_circom_frozen_mobench::{bench_prove, setup_prove, PreparedProve};
use mobench_sdk::benchmark;

#[benchmark(setup = setup_prove, per_iteration)]
pub fn bench_e15_circom_arkworks_prove(prepared: PreparedProve) {
    bench_prove(prepared);
}

mobench_sdk::export_native_c_abi!();
`,
);

console.log(`Prepared Circom-only E15 adapter at ${output}`);
