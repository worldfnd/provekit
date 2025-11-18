use {
    crate::FieldElement, ark_ff::UniformRand, rayon::prelude::*,
    whir::poly_utils::evals::EvaluationsList,
};

pub fn create_masked_polynomial(
    original: EvaluationsList<FieldElement>,
    mask: &[FieldElement],
) -> EvaluationsList<FieldElement> {
    let mut combined = Vec::with_capacity(original.num_evals() * 2);
    combined.extend_from_slice(original.evals());
    combined.extend_from_slice(mask);
    EvaluationsList::new(combined)
}

pub fn generate_random_multilinear_polynomial(num_vars: usize) -> Vec<FieldElement> {
    let num_elements = 1 << num_vars;
    let mut elements = Vec::with_capacity(num_elements);

    // TODO(px): find the optimal chunk size
    const CHUNK_SIZE: usize = 32;

    // Get access to the uninitialized memory
    let spare = elements.spare_capacity_mut();

    // Fill the uninitialized memory in parallel using chunked approach
    spare.par_chunks_mut(CHUNK_SIZE).for_each(|chunk| {
        let mut rng = ark_std::rand::thread_rng();
        for element in chunk {
            element.write(FieldElement::rand(&mut rng));
        }
    });

    unsafe {
        elements.set_len(num_elements);
    }

    elements
}
