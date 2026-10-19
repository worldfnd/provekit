//! Public-input and return regressions on `noir-examples/power`
//! (`fn main(x: Field, y: pub Field) -> pub Field`), whose Mavros artifacts
//! are committed next to it. Regenerate them with the pinned Mavros revision:
//! `mavros compile <dir> --r1cs-output <dir>/r1cs.bin --binary-output
//! <dir>/basic.json`.

use {
    anyhow::Result,
    ark_ff::Field as _,
    noirc_abi::{input_parser::InputValue, InputMap},
    provekit_backend_bn254::{
        Bn254Field, FieldElement, NoirProofScheme, Prove, ProvekitProof, Prover, Verifier, Verify,
    },
    provekit_common::{HashConfig, WitnessCommitmentMode},
    provekit_r1cs_compiler::MavrosCompiler,
    std::path::{Path, PathBuf},
};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../noir-examples/power")
}

fn compile(basic: &Path, r1cs: &Path) -> Result<NoirProofScheme> {
    MavrosCompiler::compile(
        basic,
        r1cs,
        HashConfig::Sha256,
        WitnessCommitmentMode::default(),
    )
}

fn fixture_scheme() -> NoirProofScheme {
    let dir = fixture_dir();
    compile(&dir.join("basic.json"), &dir.join("r1cs.bin")).unwrap()
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
fn declared_return_is_optional_and_checked() {
    let scheme = fixture_scheme();
    let proof = prove(&scheme, None).expect("the circuit computes its return");
    assert_eq!(proof.public_inputs.0, vec![1024u64.into(), 1024u64.into()]);
    verify(&scheme, &proof).unwrap();
    let err = prove(&scheme, Some(1025)).expect_err("a wrong declared return is rejected");
    assert!(format!("{err:#}").contains("return"), "{err:#}");
}

#[test]
fn verifier_is_bound_to_the_mavros_digest() {
    let scheme = fixture_scheme();
    let proof = prove(&scheme, None).unwrap();
    verify(&scheme, &proof).unwrap();
    for digest in [None, Some([7u8; 32])] {
        let mut verifier = Verifier::from_noir_proof_scheme(scheme.clone());
        verifier.mavros_digest = digest;
        assert!(verifier.verify(&proof).is_err(), "{digest:?}");
    }
}
