use {
    crate::FieldElement,
    ark_ff::{UniformRand, Zero},
    rayon::prelude::*,
    whir::poly_utils::evals::EvaluationsList,
};

pub fn create_masked_polynomial(
    original: &EvaluationsList<FieldElement>,
    mask: &[FieldElement],
) -> EvaluationsList<FieldElement> {
    let mut combined = Vec::with_capacity(original.num_evals() * 2);
    combined.extend_from_slice(original.evals());
    combined.extend_from_slice(mask);
    EvaluationsList::new(combined)
}

pub fn generate_random_multilinear_polynomial(num_vars: usize) -> Vec<FieldElement> {
    let num_elements = 1 << num_vars;
    let mut elements = vec![FieldElement::zero(); num_elements];

    // Fill the pre-allocated vector in parallel using chunked approach
    // Each thread gets its own RNG instance and processes a chunk of elements
    elements
        .par_chunks_mut(rayon::current_num_threads().max(1) * 4)
        .for_each(|chunk| {
            let mut rng = ark_std::rand::thread_rng();
            for element in chunk {
                *element = FieldElement::rand(&mut rng);
            }
        });

    elements
}
