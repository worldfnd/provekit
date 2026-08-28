import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const [projectArg, artifactArg] = process.argv.slice(2);
if (!projectArg || !artifactArg) {
  throw new Error(
    "usage: bun run configure-mopro-native.ts <mopro-project> <webauthn-artifact-root>",
  );
}

const project = resolve(projectArg);
const artifacts = resolve(artifactArg);
const cargoPath = join(project, "Cargo.toml");
const buildPath = join(project, "build.rs");
const libPath = join(project, "src/lib.rs");
const vectorRoot = join(project, "test-vectors/circom");
const benchmarkModuleSource = join(
  import.meta.dir,
  "../mopro/webauthn_mobench.rs",
);
const benchmarkModuleDestination = join(project, "src/webauthn_mobench.rs");
const noirBenchmarkModuleSource = join(
  import.meta.dir,
  "../mopro/noir_mobench.rs",
);
const noirBenchmarkModuleDestination = join(project, "src/noir_mobench.rs");
const hostRunnerSource = join(import.meta.dir, "../mopro/mobench_host.rs");
const hostRunnerDestination = join(project, "src/bin/mobench-host.rs");
const noirSrsHostSource = join(import.meta.dir, "../mopro/noir_srs_host.rs");
const noirSrsHostDestination = join(project, "src/bin/noir-srs-host.rs");
const ios15CharconvShimSource = join(
  import.meta.dir,
  "../mopro/ios15_charconv_shim.cpp",
);
const ios15CharconvShimDestination = join(project, "ios15_charconv_shim.cpp");
const datSource = join(
  artifacts,
  "webauthn_default_cpp/webauthn_default.dat",
);
const wasmSource = join(
  artifacts,
  "webauthn_default_js/webauthn_default.wasm",
);
const inputSource = join(
  artifacts,
  "../../sources/webauth-circom/scripts/input_webauthn_default.json",
);

for (const path of [
  cargoPath,
  buildPath,
  libPath,
  datSource,
  wasmSource,
  inputSource,
  benchmarkModuleSource,
  noirBenchmarkModuleSource,
  hostRunnerSource,
  noirSrsHostSource,
  ios15CharconvShimSource,
]) {
  if (!existsSync(path)) {
    throw new Error(`required path does not exist: ${path}`);
  }
}

function replaceRequired(
  content: string,
  before: string,
  after: string,
  label: string,
): string {
  if (content.includes(after)) return content;
  if (!content.includes(before)) {
    throw new Error(`cannot configure ${label}: expected template text missing`);
  }
  return content.replace(before, after);
}

let cargo = readFileSync(cargoPath, "utf8");
const mobenchDependency =
  'mobench-sdk = "0.2.0"';
cargo = cargo.replace(/^mobench-sdk = .*$/m, mobenchDependency);
if (cargo.includes('mopro-ffi = { version = "=0.3.7", features = ["witnesscalc"] }')) {
  cargo = cargo.replace(
    'mopro-ffi = { version = "=0.3.7", features = ["witnesscalc"] }',
    'mopro-ffi = { version = "=0.3.7" }',
  );
}
cargo = replaceRequired(
  cargo,
  'circom-prover = "0.1"\nrust-witness  = "0.1"',
  'circom-prover = "=0.1.4"\nrust-witness = "0.1"',
  "Circom prover dependencies",
);
cargo = cargo.replace(
  'circom-prover = { version = "=0.1.4", features = ["witnesscalc"] }\nwitnesscalc-adapter = "0.1"',
  'circom-prover = "=0.1.4"\nrust-witness = "0.1"',
);
if (!cargo.includes(mobenchDependency)) {
  cargo = cargo.replace(
    'anyhow = "1.0.99"',
    `anyhow = "1.0.99"\ninventory = "0.3"\n${mobenchDependency}`,
  );
}
if (!cargo.includes('inventory = "0.3"')) {
  cargo = cargo.replace(
    mobenchDependency,
    `inventory = "0.3"\n${mobenchDependency}`,
  );
}
if (!cargo.includes('noirc_abi = { git = "https://github.com/noir-lang/noir.git", rev = "v1.0.0-beta.19" }')) {
  cargo = cargo.replace(
    'serde_json = "1.0.94"',
    'serde_json = "1.0.94"\nnoirc_abi = { git = "https://github.com/noir-lang/noir.git", rev = "v1.0.0-beta.19" }',
  );
}
if (!cargo.includes("\n[workspace]\n")) cargo += "\n[workspace]\n";
if (!cargo.includes('\ncc = "1"\n')) {
  cargo = cargo.replace(
    "# CIRCOM_BUILD_DEPENDENCIES",
    '# CIRCOM_BUILD_DEPENDENCIES\ncc = "1"',
  );
}
writeFileSync(cargoPath, cargo);

let build = readFileSync(buildPath, "utf8");
build = replaceRequired(
  build,
  'witnesscalc_adapter::build_and_link("./test-vectors/circom");',
  'rust_witness::transpile::transpile_wasm("./test-vectors/circom".to_string());',
  "rust-witness build hook",
);
if (!build.includes("ios15_charconv_shim.cpp")) {
  build = build.replace(
    "fn main() {",
    `fn main() {
    let target = std::env::var("TARGET").expect("TARGET");
    if target.contains("apple-ios") {
        cc::Build::new()
            .cpp(true)
            .file("ios15_charconv_shim.cpp")
            .flag("-std=c++17")
            .cargo_metadata(false)
            .compile("ios15-charconv-shim");
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=static:+bundle=ios15-charconv-shim");
    }`,
  );
}
if (!build.includes("static:+bundle=ios15-charconv-shim")) {
  build = replaceRequired(
    build,
    `            .flag("-std=c++17")
            .compile("ios15-charconv-shim");`,
    `            .flag("-std=c++17")
            .cargo_metadata(false)
            .compile("ios15-charconv-shim");
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=static:+bundle=ios15-charconv-shim");`,
    "bundled iOS 15 charconv shim",
  );
}
writeFileSync(buildPath, build);
copyFileSync(ios15CharconvShimSource, ios15CharconvShimDestination);

let lib = readFileSync(libPath, "utf8");
lib = replaceRequired(
  lib,
  `mod witness {
    rust_witness::witness!(multiplier2);
}

crate::set_circom_circuits! {
    ("multiplier2_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::multiplier2_witness)),
}`,
  `mod witness {
    rust_witness::witness!(webauthndefault);
}

crate::set_circom_circuits! {
    ("webauthn_default_benchmark.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::webauthndefault_witness)),
}`,
  "Circom WebAuthn registration",
);
lib = lib.replace(
  `witnesscalc_adapter::witness!(webauthndefault);

crate::set_circom_circuits! {
    ("webauthn_default_benchmark.zkey", circom_prover::witness::WitnessFn::WitnessCalc(webauthndefault_witness)),
}`,
  `mod witness {
    rust_witness::witness!(webauthndefault);
}

crate::set_circom_circuits! {
    ("webauthn_default_benchmark.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::webauthndefault_witness)),
}`,
);
if (
  !lib.includes("requires the cached WebAuthn benchmark zkey") &&
  !lib.includes("fn test_webauthn_default()")
) {
  lib = replaceRequired(
    lib,
    "    #[test]\n    fn test_multiplier2() {",
    '    #[test]\n    #[ignore = "requires the cached WebAuthn benchmark zkey"]\n    fn test_multiplier2() {',
    "sample Circom test guard",
  );
}
const mobenchMarker = "// MOBENCH_WEBAUTHN_DECLARATIONS";
if (lib.includes(mobenchMarker)) {
  lib = lib.slice(0, lib.indexOf(mobenchMarker)).trimEnd() + "\n";
} else {
  lib = lib.replace(
    "\nmod webauthn_mobench;\nmobench_sdk::export_native_c_abi!();\n",
    "\n",
  );
}
lib += `
// MOBENCH_WEBAUTHN_DECLARATIONS
mod webauthn_mobench;
mod noir_mobench;
use mobench_sdk::benchmark;
use webauthn_mobench::{
    setup_inputs as setup_webauthn_arkworks_inputs,
    setup_prove as setup_webauthn_arkworks_prove,
    setup_verify as setup_webauthn_arkworks_verify,
};
use noir_mobench::{
    setup_oprf_input_to_proof,
    setup_oprf_prove as setup_oprf_barretenberg_prove,
    setup_oprf_verify as setup_oprf_barretenberg_verify,
    setup_passport_input_to_proof,
    setup_passport_p1_input_to_proof,
    setup_passport_prove as setup_passport_barretenberg_prove,
    setup_passport_verify as setup_passport_barretenberg_verify,
    setup_webauthn_input_to_proof,
    setup_webauthn_prove as setup_webauthn_barretenberg_prove,
    setup_webauthn_verify as setup_webauthn_barretenberg_verify,
};

#[benchmark(setup = setup_webauthn_input_to_proof, per_iteration)]
pub fn bench_webauthn_barretenberg_input_to_proof(prepared: noir_mobench::PreparedInputToProof) {
    noir_mobench::bench_input_to_proof_impl(prepared);
}

#[benchmark(setup = setup_passport_input_to_proof, per_iteration)]
pub fn bench_passport_barretenberg_input_to_proof(prepared: noir_mobench::PreparedInputToProof) {
    noir_mobench::bench_input_to_proof_impl(prepared);
}

#[benchmark(setup = setup_passport_p1_input_to_proof, per_iteration)]
pub fn bench_passport_p1_barretenberg_input_to_proof(prepared: noir_mobench::PreparedInputToProof) {
    noir_mobench::bench_input_to_proof_impl(prepared);
}

#[benchmark(setup = setup_oprf_input_to_proof, per_iteration)]
pub fn bench_oprf_barretenberg_input_to_proof(prepared: noir_mobench::PreparedInputToProof) {
    noir_mobench::bench_input_to_proof_impl(prepared);
}

#[benchmark(setup = setup_webauthn_arkworks_inputs, per_iteration)]
pub fn bench_webauthn_arkworks_witness(inputs: String) {
    webauthn_mobench::bench_webauthn_arkworks_witness_impl(inputs);
}

#[benchmark(setup = setup_webauthn_arkworks_prove, per_iteration)]
pub fn bench_webauthn_arkworks_prove(prepared: webauthn_mobench::PreparedProve) {
    webauthn_mobench::bench_webauthn_arkworks_prove_impl(prepared);
}

#[benchmark(setup = setup_webauthn_arkworks_verify)]
pub fn bench_webauthn_arkworks_verify(prepared: &webauthn_mobench::PreparedVerify) {
    webauthn_mobench::bench_webauthn_arkworks_verify_impl(prepared);
}

#[benchmark(setup = setup_webauthn_arkworks_inputs, per_iteration)]
pub fn bench_webauthn_arkworks_e2e(inputs: String) {
    webauthn_mobench::bench_webauthn_arkworks_e2e_impl(inputs);
}

#[benchmark(setup = setup_webauthn_barretenberg_prove, per_iteration)]
pub fn bench_webauthn_barretenberg_prove(prepared: noir_mobench::PreparedProve) {
    noir_mobench::bench_prove_impl(prepared);
}

#[benchmark(setup = setup_webauthn_barretenberg_verify)]
pub fn bench_webauthn_barretenberg_verify(prepared: &noir_mobench::PreparedVerify) {
    noir_mobench::bench_verify_impl(prepared);
}

#[benchmark(setup = setup_webauthn_barretenberg_prove, per_iteration)]
pub fn bench_webauthn_barretenberg_proof_verify(prepared: noir_mobench::PreparedProve) {
    noir_mobench::bench_proof_verify_impl(prepared);
}

#[benchmark(setup = setup_oprf_barretenberg_prove, per_iteration)]
pub fn bench_oprf_barretenberg_prove(prepared: noir_mobench::PreparedProve) {
    noir_mobench::bench_prove_impl(prepared);
}

#[benchmark(setup = setup_oprf_barretenberg_verify)]
pub fn bench_oprf_barretenberg_verify(prepared: &noir_mobench::PreparedVerify) {
    noir_mobench::bench_verify_impl(prepared);
}

#[benchmark(setup = setup_oprf_barretenberg_prove, per_iteration)]
pub fn bench_oprf_barretenberg_proof_verify(prepared: noir_mobench::PreparedProve) {
    noir_mobench::bench_proof_verify_impl(prepared);
}

#[benchmark(setup = setup_passport_barretenberg_prove, per_iteration)]
pub fn bench_passport_barretenberg_prove(prepared: noir_mobench::PreparedProve) {
    noir_mobench::bench_prove_impl(prepared);
}

#[benchmark(setup = setup_passport_barretenberg_verify)]
pub fn bench_passport_barretenberg_verify(prepared: &noir_mobench::PreparedVerify) {
    noir_mobench::bench_verify_impl(prepared);
}

#[benchmark(setup = setup_passport_barretenberg_prove, per_iteration)]
pub fn bench_passport_barretenberg_proof_verify(prepared: noir_mobench::PreparedProve) {
    noir_mobench::bench_proof_verify_impl(prepared);
}

mobench_sdk::export_native_c_abi!();
`;
writeFileSync(libPath, lib);

copyFileSync(datSource, join(vectorRoot, "webauthndefault.dat"));
copyFileSync(wasmSource, join(vectorRoot, "webauthndefault.wasm"));
copyFileSync(inputSource, join(vectorRoot, "input_webauthn_default.json"));
copyFileSync(benchmarkModuleSource, benchmarkModuleDestination);
copyFileSync(noirBenchmarkModuleSource, noirBenchmarkModuleDestination);
copyFileSync(hostRunnerSource, hostRunnerDestination);
copyFileSync(noirSrsHostSource, noirSrsHostDestination);

console.log(`Configured Mopro native adapters at ${project}`);
