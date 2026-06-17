use {
    noirc_artifacts::program::ProgramArtifact, provekit_noir::NoirWitnessGenerator,
    std::num::NonZeroU32,
};

/// Build a [`NoirWitnessGenerator`] from a compiled Noir program and the
/// ACIR→R1CS witness index map.
///
/// The generator type lives in `provekit-noir` (the frontend crate); this
/// compiler owns the program-derived construction logic and hands the derived
/// ABI + witness map to the crate's plain constructor.
pub fn build_noir_witness_generator(
    program: &ProgramArtifact,
    mut witness_map: Vec<Option<NonZeroU32>>,
    r1cs_witnesses: usize,
) -> NoirWitnessGenerator {
    let abi = program.abi.clone();
    assert!(witness_map
        .iter()
        .filter_map(|n| *n)
        .all(|n| (n.get() as usize) < r1cs_witnesses));

    // Take only the prefix of witness map relevant for Noir inputs
    let num_inputs = abi.field_count() as usize;
    witness_map.truncate(num_inputs);
    NoirWitnessGenerator::new(abi, witness_map)
}
