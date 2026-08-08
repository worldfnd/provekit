use {
    base64::Engine,
    flate2::{write::DeflateEncoder, Compression},
    std::{
        env, fs,
        io::{self, Write},
        path::{Path, PathBuf},
    },
};

struct FixtureArtifact {
    output_file:       &'static str,
    source_target_rel: &'static str,
}

const FIXTURE_ARTIFACTS: &[FixtureArtifact] = &[
    FixtureArtifact {
        output_file:       "complete_age_check.json",
        source_target_rel: "noir-examples/noir-passport-monolithic/complete_age_check/target/\
                            complete_age_check.json",
    },
    FixtureArtifact {
        output_file:       "t_add_dsc_720.json",
        source_target_rel: "noir-examples/noir-passport/merkle_age_check/target/t_add_dsc_720.json",
    },
    FixtureArtifact {
        output_file:       "t_add_id_data_720.json",
        source_target_rel: "noir-examples/noir-passport/merkle_age_check/target/t_add_id_data_720.\
                            json",
    },
    FixtureArtifact {
        output_file:       "t_add_integrity_commit.json",
        source_target_rel: "noir-examples/noir-passport/merkle_age_check/target/\
                            t_add_integrity_commit.json",
    },
    FixtureArtifact {
        output_file:       "t_attest.json",
        source_target_rel: "noir-examples/noir-passport/merkle_age_check/target/t_attest.json",
    },
    FixtureArtifact {
        output_file:       "oprf.json",
        source_target_rel: "noir-examples/oprf/target/oprf.json",
    },
    FixtureArtifact {
        output_file:       "passport_p1.json",
        source_target_rel: "target/v1-benchmarks/passport-p1-beta11/target/passport_p1.json",
    },
    FixtureArtifact {
        output_file:       "p256.json",
        source_target_rel: "noir-examples/p256_bigcurve/target/p256.json",
    },
    FixtureArtifact {
        output_file:       "webauthn_assertion.json",
        source_target_rel: "benchmarks/v1/noir/webauthn_assertion/target/webauthn_assertion.json",
    },
];

const COMPLETE_AGE_CHECK_INPUT: &str = "complete_age_check.Prover.toml";
const OPRF_INPUT: &str = "oprf.Prover.toml";
const PASSPORT_P1_INPUT: &str = "passport_p1.Prover.toml";

fn copy_if_present(from: &Path, to: &Path) -> io::Result<bool> {
    if from.exists() {
        fs::copy(from, to)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn env_flag_enabled(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| value != "0" && value != "false")
}

fn strip_host_width_debug_symbols(path: &Path) {
    let contents = fs::read_to_string(path).expect("read mobile benchmark artifact");
    let mut artifact: serde_json::Value =
        serde_json::from_str(&contents).expect("deserialize mobile benchmark artifact JSON");
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(br#"{"debug_infos":[]}"#)
        .expect("compress empty Noir debug metadata");
    let compressed = encoder.finish().expect("finish empty Noir debug metadata");
    artifact["debug_symbols"] =
        serde_json::Value::String(base64::prelude::BASE64_STANDARD.encode(compressed));
    fs::write(
        path,
        serde_json::to_vec(&artifact).expect("serialize mobile benchmark artifact"),
    )
    .expect("write 32-bit-safe mobile benchmark artifact");
}

fn require_provekit_noir_version(path: &Path) {
    let contents = fs::read_to_string(path).expect("read mobile benchmark artifact");
    let artifact: serde_json::Value =
        serde_json::from_str(&contents).expect("deserialize mobile benchmark artifact JSON");
    let version = artifact["noir_version"]
        .as_str()
        .expect("mobile benchmark artifact must declare noir_version");
    assert!(
        version.starts_with("1.0.0-beta.11+"),
        "{} was compiled by incompatible Noir {}; ProveKit V1 requires beta.11 artifacts",
        path.display(),
        version
    );
}

fn main() {
    if env::var("TARGET").is_ok_and(|target| target.contains("apple-ios")) {
        chkstk_stub::build();
    }
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .expect("bench-mobile crate should live at workspace root")
        .to_path_buf();
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("bench_mobile_fixtures");
    let frozen_artifact_dir = workspace_dir.join("target/v1-benchmarks/provekit-beta11-artifacts");
    let artifact_dir = env::var_os("PROVEKIT_MOBILE_BENCH_ARTIFACT_DIR")
        .map(PathBuf::from)
        .or_else(|| frozen_artifact_dir.is_dir().then_some(frozen_artifact_dir));
    let require_artifacts = env_flag_enabled("PROVEKIT_REQUIRE_MOBILE_BENCH_ARTIFACTS")
        || env_flag_enabled("MOBENCH_CI_PREPARE");
    let target_pointer_width =
        env::var("CARGO_CFG_TARGET_POINTER_WIDTH").expect("CARGO_CFG_TARGET_POINTER_WIDTH");

    println!("cargo:rerun-if-env-changed=PROVEKIT_REQUIRE_MOBILE_BENCH_ARTIFACTS");
    println!("cargo:rerun-if-env-changed=MOBENCH_CI_PREPARE");

    fs::create_dir_all(&out_dir).expect("create generated fixture output dir");

    for (output_name, source_rel) in [
        (
            COMPLETE_AGE_CHECK_INPUT,
            "noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml",
        ),
        (OPRF_INPUT, "noir-examples/oprf/Prover.toml"),
        (
            PASSPORT_P1_INPUT,
            "target/v1-benchmarks/passport-p1-beta11/Prover.toml",
        ),
    ] {
        let frozen_input = artifact_dir.as_ref().map(|dir| dir.join(output_name));
        let source_input = workspace_dir.join(source_rel);
        let selected_input = frozen_input
            .as_ref()
            .filter(|path| path.is_file())
            .unwrap_or(&source_input);
        if require_artifacts && frozen_input.as_ref().is_none_or(|path| !path.is_file()) {
            let expected = frozen_input
                .as_ref()
                .map_or_else(|| "<unset>".to_owned(), |path| path.display().to_string());
            panic!("missing required frozen beta.11 input at {expected}");
        }
        fs::copy(selected_input, out_dir.join(output_name))
            .unwrap_or_else(|error| panic!("copy {output_name}: {error}"));
        println!("cargo:rerun-if-changed={}", selected_input.display());
    }

    for artifact in FIXTURE_ARTIFACTS {
        let out_path = out_dir.join(artifact.output_file);
        let mut copied = false;

        if let Some(dir) = artifact_dir.as_ref() {
            copied = copy_if_present(&dir.join(artifact.output_file), &out_path)
                .expect("copy mobile benchmark artifact from override dir");
            println!("cargo:rerun-if-env-changed=PROVEKIT_MOBILE_BENCH_ARTIFACT_DIR");
        }

        if !copied {
            let source_path = workspace_dir.join(artifact.source_target_rel);
            copied = copy_if_present(&source_path, &out_path)
                .expect("copy mobile benchmark artifact from Noir target dir");
            println!("cargo:rerun-if-changed={}", source_path.display());
        }

        if !copied {
            println!(
                "cargo:warning=missing generated Noir artifact {}; run the mobile fixture \
                 generation workflow step before executing bench-mobile tests",
                artifact.output_file
            );
            if require_artifacts {
                panic!(
                    "missing required generated Noir artifact {} at {}; run \
                     bench-mobile/scripts/generate-fixtures.sh before building mobile benchmark \
                     artifacts",
                    artifact.output_file,
                    workspace_dir.join(artifact.source_target_rel).display()
                );
            }
            fs::write(&out_path, "{}\n").expect("write placeholder mobile benchmark artifact");
        }

        if copied && target_pointer_width == "32" {
            // Noir debug metadata contains host-sized `usize` ranges. Nargo
            // emits those ranges on the 64-bit preparation host, and serde
            // rejects them when a 32-bit device decodes the artifact. Debug
            // symbols are not consumed by proving or verification, so omit
            // them only from 32-bit benchmark bundles while preserving the
            // ABI, bytecode, circuit hash, and witness inputs.
            strip_host_width_debug_symbols(&out_path);
        }
        if copied {
            require_provekit_noir_version(&out_path);
        }
    }
}
