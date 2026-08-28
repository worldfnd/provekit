use std::{env, path::PathBuf};

fn main() {
    chkstk_stub::build();

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let benchmark_root = manifest_dir
        .parent()
        .expect("WebAuthn witness helper lives below benchmarks/v1");
    let source = benchmark_root.join("circom/web/dist/assets/webauthn/webauthn_default.wasm");
    assert!(
        source.is_file(),
        "missing live witness WASM: {}",
        source.display()
    );
    println!("cargo:rerun-if-changed={}", source.display());

    let witness_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"))
        .join("live-witness-wasm");
    std::fs::create_dir_all(&witness_dir).expect("create live witness WASM directory");
    std::fs::copy(
        &source,
        witness_dir.join("webauthndefault.wasm"),
    )
    .expect("copy live witness WASM");
    rust_witness::transpile::transpile_wasm(witness_dir.to_string_lossy().into_owned());
}
