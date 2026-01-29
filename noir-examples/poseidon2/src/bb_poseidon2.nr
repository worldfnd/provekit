pub mod bb {

    use std::hash::poseidon2_permutation;

    #[export]
    pub fn bb_perm4(state: [Field; 4]) -> [Field; 4] {
        poseidon2_permutation(state, 4)
    }

}
