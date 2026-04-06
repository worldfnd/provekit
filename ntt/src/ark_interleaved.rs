use {crate::{define_ntt_loops, extend_roots_table}, ark_bn254::Fr};

define_ntt_loops!(interleaved_ntt_nr, Fr, ark_kernel);

pub fn ntt_nr_ark(values: &mut [Fr], codeword_size: usize, num_groups: usize) {
    let new_root = extend_roots_table(codeword_size);
    interleaved_ntt_nr(&new_root.0, values, codeword_size, num_groups)
}

#[inline(always)]
fn ark_kernel(even: &mut Fr, odd: &mut Fr, omega: &Fr) {
    (*even, *odd) = (*even + omega * odd, *even - omega * odd)
}
