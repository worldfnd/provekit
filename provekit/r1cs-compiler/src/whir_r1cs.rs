use {
    provekit_common::{utils::next_power_of_two, WhirConfig, WhirR1CSScheme, R1CS, FieldElement},
    whir::parameters::{
        default_max_pow, DeduplicationStrategy, FoldingFactor, MerkleProofStrategy,
        MultivariateParameters, ProtocolParameters, SoundnessType,
    },
};

pub trait WhirR1CSSchemeBuilder {
    fn new_for_r1cs(r1cs: &R1CS) -> Self;

    fn new_whir_config_for_size(num_variables: usize, batch_size: usize) -> WhirConfig;
}

// fn pad_columns_to_nv(cols: &mut [Vec<FieldElement>], num_variables: usize) {
//     let target_len = 1usize << num_variables;
//     for col in cols.iter_mut() {
//         if col.len() < target_len {
//             col.resize(target_len, FieldElement::zero());
//         }
//     }
// }
const MIN_DOMAIN_LOG2: usize = 12; // 4096. Pick 12 for dev; make it a cfg later.
const MIN_SUMCHECK_LOG2: usize = 1;
impl WhirR1CSSchemeBuilder for WhirR1CSScheme {
    fn new_for_r1cs(r1cs: &R1CS) -> Self {
        // m is equal to ceiling(log(number of variables in constraint system)). It is
        // equal to the log of the width of the matrices.
//        let m = next_power_of_two(r1cs.num_witnesses());

        // m_0 is equal to ceiling(log(number_of_constraints)). It is equal to the
        // number of variables in the multilinear polynomial we are running our sumcheck
        // on.
  //      let m_0 = next_power_of_two(r1cs.num_constraints());
 // don’t let m_0 be 0
let m_raw  = next_power_of_two(r1cs.num_witnesses() + 1 );
let m0_raw = next_power_of_two(r1cs.num_constraints());

// NEW: clamp them to the floors
let mut m   = m_raw.max(MIN_DOMAIN_LOG2);
let m_0 = m0_raw.max(MIN_SUMCHECK_LOG2);
if m== MIN_DOMAIN_LOG2{
    m+=1;
}
        // Whir parameters
        Self {
            m: m ,
            m_0,
            a_num_terms: next_power_of_two(r1cs.a().iter().count()),
            whir_witness: Self::new_whir_config_for_size(m , 2),
            whir_for_hiding_spartan: Self::new_whir_config_for_size(
                next_power_of_two(4 * m_0) + 1 ,
                2,
            ),
        }
    }

    fn new_whir_config_for_size(num_variables: usize, batch_size: usize) -> WhirConfig {
        let nv = num_variables.max(MIN_DOMAIN_LOG2);
let folding = if nv < 2 { FoldingFactor::Constant(1) } else { FoldingFactor::Constant(4) };
// ... build WhirConfig with nv and folding ...
// let mv_params = MultivariateParameters::new(num_variables);
        let mv_params = MultivariateParameters::new(nv);
        let whir_params = ProtocolParameters {
            initial_statement: true,
            security_level: 128,
            pow_bits: default_max_pow(nv, 1),
            folding_factor: folding,
            leaf_hash_params: (),
            two_to_one_params: (),
            soundness_type: SoundnessType::ConjectureList,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: 1,
            batch_size,
            deduplication_strategy: DeduplicationStrategy::Disabled,
            merkle_proof_strategy: MerkleProofStrategy::Uncompressed,
        };
        WhirConfig::new(mv_params, whir_params)
    }
}
