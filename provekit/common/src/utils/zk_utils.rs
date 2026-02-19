use {crate::FieldElement, ark_ff::UniformRand, rayon::prelude::*};

pub fn create_masked_polynomial(
    mut original: Vec<FieldElement>,
    mask: &[FieldElement],
) -> Vec<FieldElement> {
    original.reserve(mask.len());
    original.extend_from_slice(mask);
    original
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
