//! Prepare one immutable local SRS large enough for all supplied Noir circuits.

use {
    noir_rs::barretenberg::{
        srs::{localsrs::LocalSrs, netsrs::NetSrs},
        utils::{compute_subgroup_size, get_circuit_size},
    },
    serde_json::Value,
    std::{env, fs, path::PathBuf, process::ExitCode},
};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(output) = args.next() else {
        eprintln!("usage: noir-srs-host <output.srs> <circuit.json>...");
        return ExitCode::FAILURE;
    };
    let circuits: Vec<String> = args.collect();
    if circuits.is_empty() {
        eprintln!("at least one circuit is required");
        return ExitCode::FAILURE;
    }

    let mut required_points = 0u32;
    for path in &circuits {
        let json: Value = serde_json::from_slice(
            &fs::read(path).unwrap_or_else(|error| panic!("read {path}: {error}")),
        )
        .unwrap_or_else(|error| panic!("parse {path}: {error}"));
        let bytecode = json["bytecode"]
            .as_str()
            .unwrap_or_else(|| panic!("{path} has no bytecode"));
        let dyadic_gates = get_circuit_size(bytecode, false);
        assert!(
            dyadic_gates > 0,
            "failed to inspect circuit size for {path}"
        );
        let prover_points = compute_subgroup_size(
            dyadic_gates
                .checked_mul(8)
                .expect("UltraHonk SRS point count overflow"),
        )
        .checked_add(1)
        .expect("UltraHonk SRS point count overflow");
        eprintln!("{path}: dyadic_gates={dyadic_gates} srs_points={prover_points}");
        required_points = required_points.max(prover_points);
    }

    if env::var_os("NOIR_SRS_DRY_RUN").is_some() {
        eprintln!("dry run: required_points={required_points}");
        return ExitCode::SUCCESS;
    }

    let output = PathBuf::from(output);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("create {}: {error}", parent.display()));
    }
    let local = LocalSrs(NetSrs::new(required_points).to_srs());
    local.save(output.to_str());
    eprintln!("wrote {} points to {}", required_points, output.display());
    ExitCode::SUCCESS
}
