use std::{
    env, fs, io,
    path::{Path, PathBuf},
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
        output_file:       "p256.json",
        source_target_rel: "noir-examples/p256_bigcurve/target/p256.json",
    },
];

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

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .expect("bench-mobile crate should live at workspace root")
        .to_path_buf();
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("bench_mobile_fixtures");
    let artifact_dir = env::var_os("PROVEKIT_MOBILE_BENCH_ARTIFACT_DIR").map(PathBuf::from);
    let require_artifacts = env_flag_enabled("PROVEKIT_REQUIRE_MOBILE_BENCH_ARTIFACTS")
        || env_flag_enabled("MOBENCH_CI_PREPARE");

    println!("cargo:rerun-if-env-changed=PROVEKIT_REQUIRE_MOBILE_BENCH_ARTIFACTS");
    println!("cargo:rerun-if-env-changed=MOBENCH_CI_PREPARE");

    fs::create_dir_all(&out_dir).expect("create generated fixture output dir");

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
    }
}
