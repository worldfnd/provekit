use {
    crate::{
        utils::uint_to_field,
        whir_r1cs::{
            skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge},
            whir_utils::GnarkConfig,
        },
        FieldElement, R1CS,
    },
    ark_poly::domain::EvaluationDomain,
    ark_serialize::CanonicalSerialize,
    ark_std::{
        ops::{Add, Mul},
        str::FromStr,
        One, Zero,
    },
    ruint::uint,
    serde::Deserialize,
    spongefish::{DomainSeparator, ProverState},
    std::{fs::File, io::Write},
    tracing::instrument,
    whir::whir::{parameters::WhirConfig, WhirProof},
};

/// 1/2 for the BN254
pub const HALF: FieldElement = uint_to_field(uint!(
    10944121435919637611123202872628637544274182200208017171849102093287904247809_U256
));

/// Calculates the degree of the next smallest power of two
pub fn next_power_of_two(n: usize) -> usize {
    let mut power = 1;
    let mut ans = 0;
    while power < n {
        power <<= 1;
        ans += 1;
    }
    ans
}

/// Pads the vector with 0 so that the number of elements in the vector is a
/// power of 2
#[instrument(skip_all)]
pub fn pad_to_power_of_two(mut witness: Vec<FieldElement>) -> Vec<FieldElement> {
    let target_len = next_power_of_two(witness.len());
    while witness.len() < 1 << target_len {
        witness.push(FieldElement::zero()); // Pad with zeros
    }
    witness
}

// /// Calculates matrix-vector product
// #[instrument(skip_all)]
// pub fn calculate_matrix_vector_product(
//     matrix_cells: &Vec<MatrixCell>,
//     witness: &Vec<FieldElement>,
//     num_constraints: usize,
// ) -> Vec<FieldElement> {
//     let mut witness_bound = vec![FieldElement::zero(); num_constraints as
// usize];     for x in matrix_cells {
//         assert!(x.signal < witness.len());
//         assert!(x.constraint < num_constraints);
//         let witness_cell = witness[x.signal as usize];
//         witness_bound[x.constraint as usize] =
//             witness_bound[x.constraint as
// usize].add(x.value.mul(witness_cell));     }
//     witness_bound
// }

/// List of evaluations for eq(r, x) over the boolean hypercube
#[instrument(skip_all)]
pub fn calculate_evaluations_over_boolean_hypercube_for_eq(
    r: &Vec<FieldElement>,
) -> Vec<FieldElement> {
    let mut ans = vec![FieldElement::from(1)];
    for x in r.iter().rev() {
        let mut left: Vec<FieldElement> = ans
            .clone()
            .into_iter()
            .map(|y| y * (FieldElement::one() - x))
            .collect();
        let right: Vec<FieldElement> = ans.into_iter().map(|y| y * x).collect();
        left.extend(right);
        ans = left;
    }
    ans
}

/// Evaluates a qubic polynomial on a value
pub fn eval_qubic_poly(poly: &Vec<FieldElement>, point: &FieldElement) -> FieldElement {
    poly[0] + *point * (poly[1] + *point * (poly[2] + *point * poly[3]))
}

/// Given a path to JSON file with sparce matrices and a witness, calculates
/// matrix-vector multiplication and returns them
#[instrument(skip_all)]
pub fn calculate_witness_bounds(
    r1cs: &R1CS,
    witness: &[FieldElement],
) -> (Vec<FieldElement>, Vec<FieldElement>, Vec<FieldElement>) {
    let witness_bound_a = pad_to_power_of_two(&r1cs.a * witness);
    let witness_bound_b = pad_to_power_of_two(&r1cs.b * witness);
    let witness_bound_c = pad_to_power_of_two(&r1cs.c * witness);
    (witness_bound_a, witness_bound_b, witness_bound_c)
}

/// Calculates a dot product of two FieldElement vectors
pub fn calculate_dot_product(a: &Vec<FieldElement>, b: &Vec<FieldElement>) -> FieldElement {
    a.iter().zip(b.iter()).map(|(&a, &b)| (a * b)).sum()
}

/// Calculates eq(r, alpha)
pub fn calculate_eq(r: &[FieldElement], alpha: &[FieldElement]) -> FieldElement {
    r.iter()
        .zip(alpha.iter())
        .fold(FieldElement::from(1), |acc, (&r, &alpha)| {
            acc * (r * alpha + (FieldElement::from(1) - r) * (FieldElement::from(1) - alpha))
        })
}

/// Calculates a random row of R1CS matrix extension. Made possible due to
/// sparseness.
#[instrument(skip_all)]
pub fn calculate_external_row_of_r1cs_matrices(
    alpha: &Vec<FieldElement>,
    r1cs: &R1CS,
) -> [Vec<FieldElement>; 3] {
    let eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let eq_alpha = &eq_alpha[..r1cs.constraints];
    [eq_alpha * &r1cs.a, eq_alpha * &r1cs.b, eq_alpha * &r1cs.c]
}

/// Writes config used for Gnark circuit to a file
#[instrument(skip_all)]
pub fn gnark_parameters(
    whir_params: &WhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>,
    merlin: &ProverState<SkyscraperSponge, FieldElement>,
    io: &DomainSeparator<SkyscraperSponge, FieldElement>,
    sums: [FieldElement; 3],
    m_0: usize,
    m: usize,
) -> GnarkConfig {
    GnarkConfig {
        log_num_constraints:    m_0,
        n_rounds:               whir_params.folding_factor.compute_number_of_rounds(m).0,
        rate:                   whir_params.starting_log_inv_rate,
        n_vars:                 m,
        folding_factor:         (0..(whir_params.folding_factor.compute_number_of_rounds(m).0))
            .map(|round| whir_params.folding_factor.at_round(round))
            .collect(),
        ood_samples:            whir_params
            .round_parameters
            .iter()
            .map(|x| x.ood_samples)
            .collect(),
        num_queries:            whir_params
            .round_parameters
            .iter()
            .map(|x| x.num_queries)
            .collect(),
        pow_bits:               whir_params
            .round_parameters
            .iter()
            .map(|x| x.pow_bits as i32)
            .collect(),
        final_queries:          whir_params.final_queries,
        final_pow_bits:         whir_params.final_pow_bits as i32,
        final_folding_pow_bits: whir_params.final_folding_pow_bits as i32,
        domain_generator:       format!(
            "{}",
            whir_params.starting_domain.backing_domain.group_gen()
        ),
        io_pattern:             String::from_utf8(io.as_bytes().to_vec()).unwrap(),
        transcript:             merlin.narg_string().to_vec(),
        transcript_len:         merlin.narg_string().to_vec().len(),
        statement_evaluations:  vec![
            sums[0].to_string(),
            sums[1].to_string(),
            sums[2].to_string(),
        ],
    }
}

/// Writes config used for Gnark circuit to a file
#[instrument(skip_all)]
pub fn write_gnark_parameters_to_file(
    whir_params: &WhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>,
    merlin: &ProverState<SkyscraperSponge, FieldElement>,
    io: &DomainSeparator<SkyscraperSponge, FieldElement>,
    sums: [FieldElement; 3],
    m_0: usize,
    m: usize,
) {
    let gnark_config = gnark_parameters(whir_params, merlin, io, sums, m_0, m);
    println!("round config {:?}", whir_params.round_parameters);
    let mut file_params = File::create("./prover/params").unwrap();
    file_params
        .write_all(serde_json::to_string(&gnark_config).unwrap().as_bytes())
        .expect("Writing gnark parameters to a file failed");
}

/// Writes proof bytes to a file
pub fn write_proof_bytes_to_file(proof: &WhirProof<SkyscraperMerkleConfig, FieldElement>) {
    let mut proof_bytes: Vec<u8> = vec![];
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    let mut file = File::create("./prover/proof").unwrap();
    file.write_all(&proof_bytes)
        .expect("Writing proof bytes to a file failed");
}
