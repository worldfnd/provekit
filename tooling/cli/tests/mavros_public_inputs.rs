//! Public-input and return-guard regressions on `noir-examples/power`
//! (`fn main(x: Field, y: pub Field) -> pub Field`), whose Mavros artifacts
//! are committed next to it. Regenerate them with the pinned Mavros revision:
//! `mavros compile <dir> --r1cs-output <dir>/r1cs.bin --binary-output
//! <dir>/basic.json`.

use {
    anyhow::Result,
    ark_ff::Field as _,
    mavros_artifacts::{InputValueOrdered, R1CSArtifact},
    mavros_vm::interpreter::run_phase1,
    noirc_abi::{input_parser::InputValue, InputMap},
    provekit_backend_bn254::{
        Bn254Field, FieldElement, NoirProofScheme, Prove, ProvekitProof, Prover, Verifier, Verify,
    },
    provekit_common::{HashConfig, WitnessCommitmentMode, R1CS},
    provekit_r1cs_compiler::MavrosCompiler,
    std::path::PathBuf,
};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../noir-examples/power")
}

fn fixture_scheme() -> NoirProofScheme {
    let dir = fixture_dir();
    MavrosCompiler::compile(
        dir.join("basic.json"),
        dir.join("r1cs.bin"),
        HashConfig::Sha256,
        WitnessCommitmentMode::default(),
    )
    .unwrap()
}

fn prove(
    scheme: &NoirProofScheme,
    declared_return: Option<u64>,
) -> Result<ProvekitProof<Bn254Field>> {
    let mut inputs = InputMap::from([
        ("x".into(), InputValue::Field(2u64.into())),
        ("y".into(), InputValue::Field(1024u64.into())),
    ]);
    if let Some(ret) = declared_return {
        inputs.insert("return".into(), InputValue::Field(ret.into()));
    }
    Prover::from_noir_proof_scheme(scheme.clone()).prove(inputs)
}

fn verify(scheme: &NoirProofScheme, proof: &ProvekitProof<Bn254Field>) -> Result<()> {
    Verifier::from_noir_proof_scheme(scheme.clone()).verify(proof)
}

fn satisfies(r1cs: &R1CS<FieldElement>, witness: &[FieldElement]) -> bool {
    let dot = |matrix: &provekit_common::SparseMatrix, row: usize| -> FieldElement {
        matrix
            .iter_row(row)
            .map(|(col, coefficient)| r1cs.interner.get(coefficient).unwrap() * witness[col])
            .sum()
    };
    (0..r1cs.num_constraints())
        .all(|row| dot(&r1cs.a, row) * dot(&r1cs.b, row) == dot(&r1cs.c, row))
}

#[test]
fn public_inputs_are_ordered_and_bound() {
    let scheme = fixture_scheme();
    let proof = prove(&scheme, Some(1024)).unwrap();
    assert_eq!(proof.public_inputs.0, vec![1024u64.into(), 1024u64.into()]);
    verify(&scheme, &proof).unwrap();
    for column in 0..2 {
        let mut tampered = proof.clone();
        tampered.public_inputs.0[column] += FieldElement::ONE;
        assert!(verify(&scheme, &tampered).is_err());
    }
}

#[test]
fn declared_return_is_required_and_checked() {
    let scheme = fixture_scheme();
    let err = prove(&scheme, None).expect_err("return is required");
    assert!(format!("{err:#}").contains("return"));
    if let Ok(proof) = prove(&scheme, Some(1025)) {
        assert!(
            verify(&scheme, &proof).is_err(),
            "wrong return must not verify"
        );
    }
}

#[test]
fn return_guard_cannot_disable_constraints() {
    let NoirProofScheme::Mavros(data) = fixture_scheme() else {
        panic!("fixture is a Mavros scheme");
    };
    let artifact =
        R1CSArtifact::from_bytes(&std::fs::read(fixture_dir().join("r1cs.bin")).unwrap()).unwrap();
    assert_eq!(data.witness_layout.post_commitment_size(), 0);
    for (guard, declared_return, valid) in [(1, 1024, true), (0, 99, false)] {
        let inputs =
            [2u64, 1024, guard, declared_return].map(|v| InputValueOrdered::Field(v.into()));
        let phase1 = run_phase1(
            &data.binary,
            data.witness_layout,
            data.constraints_layout,
            &inputs,
            None,
        )
        .unwrap();
        if !valid {
            assert!(artifact
                .r1cs()
                .unsatisfied_constraint(&phase1.out_wit_pre_comm)
                .is_none());
        }
        let witness = data.column_map.permute_witness(&phase1.out_wit_pre_comm);
        assert_eq!(satisfies(&data.r1cs, &witness), valid);
    }
}
