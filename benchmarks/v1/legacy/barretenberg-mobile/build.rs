use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=BB_V087_MOBILE_LIB_DIR");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
    if env::var_os("CARGO_FEATURE_NATIVE_V087").is_none() {
        return;
    }
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo target OS");
    let target_abi = env::var("CARGO_CFG_TARGET_ABI").unwrap_or_default();
    if target_os == "ios" && target_abi == "sim" {
        // Mobench constructs a complete XCFramework and therefore compiles
        // simulator slices even for BrowserStack device-only campaigns. The
        // simulator staticlibs may retain unresolved C ABI references: Xcode
        // selects the independently linked arm64 device slice for the IPA.
        return;
    }
    let directory = env::var_os("BB_V087_MOBILE_LIB_DIR")
        .map(PathBuf::from)
        .expect("native-v087 requires BB_V087_MOBILE_LIB_DIR");
    let adapter = directory.join("libbarretenberg_v087_mobile.a");
    let upstream = directory.join("libbarretenberg.a");
    assert!(
        adapter.is_file() && upstream.is_file(),
        "BB_V087_MOBILE_LIB_DIR must contain exact v0.87 adapter and upstream archives"
    );
    println!("cargo:rustc-link-search=native={}", directory.display());
    println!("cargo:rustc-link-lib=static=barretenberg_v087_mobile");
    println!("cargo:rustc-link-lib=static=barretenberg");
    if target_os == "android" {
        let host_prebuilt = match env::consts::OS {
            "macos" => "darwin-x86_64",
            "linux" => "linux-x86_64",
            other => panic!("unsupported Android NDK build host: {other}"),
        };
        let android_triple = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
            Ok("aarch64") => "aarch64-linux-android",
            Ok("arm") => "arm-linux-androideabi",
            Ok("x86") => "i686-linux-android",
            Ok("x86_64") => "x86_64-linux-android",
            Ok(other) => panic!("unsupported Android target architecture: {other}"),
            Err(error) => panic!("missing Android target architecture: {error}"),
        };
        let ndk = env::var_os("ANDROID_NDK_HOME")
            .map(PathBuf::from)
            .expect("Android native-v087 requires ANDROID_NDK_HOME");
        let cxx_directory = ndk
            .join("toolchains/llvm/prebuilt")
            .join(host_prebuilt)
            .join("sysroot/usr/lib")
            .join(android_triple);
        assert!(
            cxx_directory.join("libc++_static.a").is_file(),
            "ANDROID_NDK_HOME does not contain libc++_static for {android_triple}"
        );
        println!("cargo:rustc-link-search=native={}", cxx_directory.display());
        println!("cargo:rustc-link-lib=static=c++_static");
        println!("cargo:rustc-link-lib=static=c++abi");
    } else {
        println!("cargo:rustc-link-lib=c++");
    }
    if target_os == "android" || target_os == "ios" {
        println!("cargo:rustc-link-lib=z");
    }
}
