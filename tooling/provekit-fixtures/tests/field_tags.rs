//! Every proof field must carry a distinct `FIELD_ID` and `.np` magic, so one
//! field's proof is rejected by another field's verifier.
//!
//! `np_format` sees one field at a time, so only a place with every backend in
//! scope can catch two of them declaring the same `FIELD_ID`. Reading `FORMAT`
//! here is also what const-evaluates `np_format`'s collision assert for the
//! non-bn254 fields — nothing else in the workspace does.

use {
    provekit_backend_bn254::Bn254Field,
    provekit_backend_goldilocks::{GoldilocksEfField, GoldilocksField},
    provekit_common::{file::FileFormat, ProofField, ProvekitProof},
    std::collections::HashSet,
};

#[test]
fn field_tags_are_unique() {
    fn tag<P: ProofField>(name: &'static str) -> (&'static str, u8, [u8; 8]) {
        (name, P::FIELD_ID, <ProvekitProof<P> as FileFormat>::FORMAT)
    }
    let tags = [
        tag::<Bn254Field>("Bn254Field"),
        tag::<GoldilocksField>("GoldilocksField"),
        tag::<GoldilocksEfField>("GoldilocksEfField"),
    ];

    let ids: HashSet<u8> = tags.iter().map(|&(_, id, _)| id).collect();
    let magics: HashSet<[u8; 8]> = tags.iter().map(|&(_, _, magic)| magic).collect();
    let named: Vec<_> = tags
        .iter()
        .map(|&(name, id, magic)| (name, id, String::from_utf8_lossy(&magic).into_owned()))
        .collect();

    assert_eq!(ids.len(), tags.len(), "FIELD_ID collision: {named:?}");
    assert_eq!(magics.len(), tags.len(), "`.np` magic collision: {named:?}");
}
