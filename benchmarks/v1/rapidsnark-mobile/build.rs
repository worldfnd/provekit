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
}
