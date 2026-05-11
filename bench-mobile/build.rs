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
            fs::write(&out_path, "{}\n").expect("write placeholder mobile benchmark artifact");
        }
    }
}
