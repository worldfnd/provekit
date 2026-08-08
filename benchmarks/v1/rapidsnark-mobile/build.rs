use std::{env, path::PathBuf};

fn main() {
    chkstk_stub::build();

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let repository_root = manifest_dir
        .ancestors()
        .nth(3)
        .expect("benchmark crate is nested below repository root");
    let target = env::var("TARGET").expect("target");

    let default_lib_dir = if target == "aarch64-apple-ios" {
        repository_root.join("target/v1-benchmarks/native-libs/rapidsnark/aarch64-apple-ios")
    } else if target == "aarch64-apple-ios-sim" {
        repository_root.join("target/v1-benchmarks/native-libs/rapidsnark/aarch64-apple-ios-sim")
    } else if target == "x86_64-apple-ios" {
        repository_root.join("target/v1-benchmarks/native-libs/rapidsnark/x86_64-apple-ios")
    } else if target == "aarch64-apple-darwin" {
        repository_root.join("target/v1-benchmarks/native-libs/rapidsnark/aarch64-apple-darwin")
    } else if target == "aarch64-linux-android" {
        repository_root.join("target/v1-benchmarks/native-libs/rapidsnark/aarch64-linux-android")
    } else {
        panic!("unsupported Rapidsnark benchmark target: {target}");
    };
    let lib_dir = env::var_os("V1_RAPIDSNARK_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or(default_lib_dir);

    for library in ["librapidsnark.a", "libfr.a", "libfq.a", "libgmp.a"] {
        let path = lib_dir.join(library);
        assert!(
            path.is_file(),
            "missing {library} for {target}; run \
             benchmarks/v1/scripts/build-rapidsnark-ios-libs.sh"
        );
    }

    println!("cargo:rerun-if-env-changed=V1_RAPIDSNARK_LIB_DIR");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=rapidsnark");
    println!("cargo:rustc-link-lib=static=fr");
    println!("cargo:rustc-link-lib=static=fq");
    println!("cargo:rustc-link-lib=static=gmp");
    println!("cargo:rustc-link-lib=c++");
    if target.contains("android") {
        // Android's libc provides pthread symbols.
        println!("cargo:rustc-link-lib=c");
    } else {
        println!("cargo:rustc-link-lib=pthread");
    }

    let benchmark_root = manifest_dir
        .parent()
        .expect("Rapidsnark crates live below benchmarks/v1");
    let (source, output_name) = if env::var_os("CARGO_FEATURE_OPRF_NULLIFIER").is_some() {
        (
            benchmark_root.join("circom/web/dist/assets/oprf/oprf_nullifier.wasm"),
            "oprfnullifierproof.wasm",
        )
    } else if env::var_os("CARGO_FEATURE_OPRF_QUERY").is_some() {
        (
            benchmark_root.join("circom/web/dist/assets/oprf/oprf_query.wasm"),
            "oprfqueryproof.wasm",
        )
    } else if env::var_os("CARGO_FEATURE_PASSPORT_REGISTER").is_some() {
        (
            benchmark_root.join(
                "circom/web/dist/assets/passport/register_sha256_sha256_sha256_rsa_65537_4096.wasm",
            ),
            "registersha256sha256sha256rsa655374096.wasm",
        )
    } else if env::var_os("CARGO_FEATURE_PASSPORT_P1").is_some() {
        (
            repository_root
                .join("target/v1-benchmarks/circom/passport_p1/passport_p1_js/passport_p1.wasm"),
            "passportp1.wasm",
        )
    } else if env::var("CARGO_PKG_NAME")
        .expect("package name")
        .contains("webauthn")
    {
        (
            benchmark_root.join("circom/web/dist/assets/webauthn/webauthn_default.wasm"),
            "webauthndefault.wasm",
        )
    } else {
        (
            benchmark_root.join("circom/web/dist/assets/passport/vc_and_disclose.wasm"),
            "vcanddisclose.wasm",
        )
    };
    assert!(
        source.is_file(),
        "missing live witness WASM: {}",
        source.display()
    );
    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rustc-env=MOBENCH_LIVE_WITNESS_WASM_BYTES={}",
        std::fs::metadata(&source)
            .expect("read live witness WASM metadata")
            .len()
    );
    let witness_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("live-witness-wasm");
    std::fs::create_dir_all(&witness_dir).expect("create live witness WASM directory");
    std::fs::copy(&source, witness_dir.join(output_name)).expect("copy live witness WASM");
    if !env::var("CARGO_PKG_NAME")
        .expect("package name")
        .contains("oprf")
    {
        rust_witness::transpile::transpile_wasm(witness_dir.to_string_lossy().into_owned());
    }
}
