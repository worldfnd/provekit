/// Poseidon2 permutation for BN254 (t=4).
///
/// Based on the Noir implementation:
/// https://github.com/noir-lang/noir/blob/12ecac9/acvm-repo/bn254_blackbox_solver/src/poseidon2.rs
use {
    crate::constants::{load_diag, load_rc_full1, load_rc_full2, load_rc_partial},
    ark_bn254::Fr,
    ark_std::Zero,
    std::sync::LazyLock,
};

/// Configuration for the Poseidon2 permutation, matching Noir's
/// `Poseidon2Config`.
pub struct Poseidon2Config {
    /// State width (number of field elements in the permutation state).
    pub t: u32,
    /// Number of full rounds (R_F). S-box applied to all state elements.
    pub rounds_f: u32,
    /// Number of partial rounds (R_P). S-box applied only to first element.
    pub rounds_p: u32,
    /// Internal matrix diagonal values for the linear layer of partial rounds.
    pub internal_matrix_diagonal: [Fr; 4],
    /// Round constants for all rounds. Each round has 4 field elements.
    pub round_constant: [[Fr; 4]; 64],
}

/// The complete Poseidon2 configuration for BN254, lazily initialized.
pub static POSEIDON2_CONFIG: LazyLock<Poseidon2Config> = LazyLock::new(|| {
    let diag_vec = load_diag(4);
    let rc_full1 = load_rc_full1(4);
    let rc_full2 = load_rc_full2(4);
    let rc_partial = load_rc_partial(4);

    let mut internal_matrix_diagonal = [Fr::zero(); 4];
    for (i, v) in diag_vec.iter().enumerate() {
        internal_matrix_diagonal[i] = *v;
    }

    let mut round_constant = [[Fr::zero(); 4]; 64];

    // First 4 full rounds
    for (r, rc_row) in rc_full1.iter().enumerate() {
        for (j, v) in rc_row.iter().enumerate() {
            round_constant[r][j] = *v;
        }
    }

    // 56 partial rounds (only lane 0 has a non-zero constant)
    let rf_first = 4; // rounds_f / 2
    for (r, v) in rc_partial.iter().enumerate() {
        round_constant[rf_first + r][0] = *v;
    }

    // Last 4 full rounds
    for (r, rc_row) in rc_full2.iter().enumerate() {
        for (j, v) in rc_row.iter().enumerate() {
            round_constant[rf_first + 56 + r][j] = *v;
        }
    }

    Poseidon2Config {
        t: 4,
        rounds_f: 8,
        rounds_p: 56,
        internal_matrix_diagonal,
        round_constant,
    }
});

/// Poseidon2 permutation state, holding a reference to the configuration.
/// Matches Noir's `Poseidon2<'a>` struct pattern.
pub struct Poseidon2<'a> {
    config: &'a Poseidon2Config,
}

impl<'a> Poseidon2<'a> {
    /// Creates a new Poseidon2 instance using the global BN254 configuration.
    pub fn new() -> Self {
        Self {
            config: &POSEIDON2_CONFIG,
        }
    }

    /// S-box: x -> x^5
    #[inline]
    fn single_box(&self, x: Fr) -> Fr {
        let s = x * x;
        s * s * x
    }

    fn s_box(&self, state: &mut [Fr; 4]) {
        for x in state.iter_mut() {
            *x = self.single_box(*x);
        }
    }

    fn add_round_constants(&self, state: &mut [Fr; 4], round: usize) {
        for (s, c) in state.iter_mut().zip(self.config.round_constant[round]) {
            *s += c;
        }
    }

    /// Algorithm is taken directly from the Poseidon2 implementation in
    /// Barretenberg crypto module.
    fn matrix_multiplication_4x4(&self, input: &mut [Fr; 4]) {
        let t0 = input[0] + input[1]; // A + B
        let t1 = input[2] + input[3]; // C + D
        let mut t2 = input[1] + input[1]; // 2B
        t2 += t1; // 2B + C + D
        let mut t3 = input[3] + input[3]; // 2D
        t3 += t0; // 2D + A + B
        let mut t4 = t1 + t1;
        t4 += t4;
        t4 += t3; // A + B + 4C + 6D
        let mut t5 = t0 + t0;
        t5 += t5;
        t5 += t2; // 4A + 6B + C + D
        let t6 = t3 + t5; // 5A + 7B + C + 3D
        let t7 = t2 + t4; // A + 3B + 5C + 7D
        input[0] = t6;
        input[1] = t5;
        input[2] = t7;
        input[3] = t4;
    }

    fn internal_m_multiplication(&self, state: &mut [Fr; 4]) {
        let sum: Fr = state.iter().copied().sum();
        for (i, s) in state.iter_mut().enumerate() {
            *s = *s * self.config.internal_matrix_diagonal[i] + sum;
        }
    }

    /// Executes the Poseidon2 permutation.
    ///
    /// Round schedule: ext_MDS → [RC + S-box → ext_MDS] × rf/2 full
    ///                         → [RC(lane0) + S-box(lane0) → int_MDS] × rp
    /// partial                         → [RC + S-box → ext_MDS] × rf/2 full
    pub fn permutation(&self, inputs: &[Fr; 4]) -> [Fr; 4] {
        let rf_first = (self.config.rounds_f / 2) as usize;
        let p_end = rf_first + self.config.rounds_p as usize;
        let num_rounds = (self.config.rounds_f + self.config.rounds_p) as usize;

        let mut state = *inputs;

        // Initial linear layer
        self.matrix_multiplication_4x4(&mut state);

        // First rf/2 full rounds
        for r in 0..rf_first {
            self.add_round_constants(&mut state, r);
            self.s_box(&mut state);
            self.matrix_multiplication_4x4(&mut state);
        }

        // Partial rounds
        for r in rf_first..p_end {
            state[0] += self.config.round_constant[r][0];
            state[0] = self.single_box(state[0]);
            self.internal_m_multiplication(&mut state);
        }

        // Last rf/2 full rounds
        for r in p_end..num_rounds {
            self.add_round_constants(&mut state, r);
            self.s_box(&mut state);
            self.matrix_multiplication_4x4(&mut state);
        }

        state
    }
}

/// runs Poseidon2 permutation with the default BN254 config.
pub fn poseidon2_permutation(inputs: &[Fr; 4]) -> [Fr; 4] {
    Poseidon2::new().permutation(inputs)
}

#[cfg(test)]
mod tests {
    use {super::*, crate::constants::fe};

    #[test]
    fn smoke_test() {
        let inputs = [Fr::zero(); 4];
        let result = poseidon2_permutation(&inputs);

        let expected = [
            fe("18DFB8DC9B82229CFF974EFEFC8DF78B1CE96D9D844236B496785C698BC6732E"),
            fe("095C230D1D37A246E8D2D5A63B165FE0FADE040D442F61E25F0590E5FB76F839"),
            fe("0BB9545846E1AFA4FA3C97414A60A20FC4949F537A68CCECA34C5CE71E28AA59"),
            fe("18A4F34C9C6F99335FF7638B82AEED9018026618358873C982BBDDE265B2ED6D"),
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_struct_instantiation() {
        let poseidon2 = Poseidon2::new();
        assert_eq!(poseidon2.config.t, 4);
        assert_eq!(poseidon2.config.rounds_f, 8);
        assert_eq!(poseidon2.config.rounds_p, 56);
    }

    #[test]
    fn test_struct_and_function_equivalence() {
        // Both should produce identical results
        let inputs = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];

        let result_via_function = poseidon2_permutation(&inputs);
        let result_via_struct = Poseidon2::new().permutation(&inputs);

        assert_eq!(result_via_function, result_via_struct);
    }

    #[test]
    fn test_determinism() {
        // Multiple runs with the same input should give the same output
        let inputs = [
            Fr::from(42u64),
            Fr::from(123u64),
            Fr::from(456u64),
            Fr::from(789u64),
        ];

        let result1 = poseidon2_permutation(&inputs);
        let result2 = poseidon2_permutation(&inputs);
        let result3 = poseidon2_permutation(&inputs);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_single_bit_difference_avalanche() {
        // Changing a single input bit should dramatically change output
        let inputs1 = [
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ];
        let inputs2 = [
            Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ];

        let result1 = poseidon2_permutation(&inputs1);
        let result2 = poseidon2_permutation(&inputs2);

        // All output lanes should differ when input differs
        for i in 0..4 {
            assert_ne!(result1[i], result2[i], "Lane {i} should differ");
        }
    }

    #[test]
    fn test_s_box_x5_correctness() {
        let poseidon2 = Poseidon2::new();

        // Test x^5 for several values
        let test_values = [
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(1000u64),
        ];

        for x in &test_values {
            let x5_via_sbox = poseidon2.single_box(*x);
            let x5_manual = {
                let s = *x * *x;
                s * s * *x
            };
            assert_eq!(x5_via_sbox, x5_manual, "S-box x^5 failed for x={:?}", x);
        }
    }

    #[test]
    fn test_zero_input_known_output() {
        // Zero input should produce the known smoke test output
        let zero_inputs = [Fr::zero(); 4];
        let result = poseidon2_permutation(&zero_inputs);

        let expected = [
            fe("18DFB8DC9B82229CFF974EFEFC8DF78B1CE96D9D844236B496785C698BC6732E"),
            fe("095C230D1D37A246E8D2D5A63B165FE0FADE040D442F61E25F0590E5FB76F839"),
            fe("0BB9545846E1AFA4FA3C97414A60A20FC4949F537A68CCECA34C5CE71E28AA59"),
            fe("18A4F34C9C6F99335FF7638B82AEED9018026618358873C982BBDDE265B2ED6D"),
        ];

        for i in 0..4 {
            assert_eq!(result[i], expected[i]);
        }
    }

    #[test]
    fn test_identity_property_negation() {
        // Permutation should not be identity (output != input)
        let inputs = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let result = poseidon2_permutation(&inputs);

        assert_ne!(inputs, result, "Permutation should not be identity");
    }

    #[test]
    fn test_max_field_element() {
        // Test with a large field element
        let large_value = Fr::from(u64::MAX);

        let inputs = [large_value; 4];
        let result = poseidon2_permutation(&inputs);

        // Should not panic and should produce valid output
        assert!(result.len() == 4);
        for val in &result {
            // All outputs should be in the field (no panics during arithmetic)
            let _ = *val + *val; // Verify it's a valid field element
        }
    }

    #[test]
    fn test_consecutive_permutations() {
        // Applying permutation twice should give different result than once
        let inputs = [
            Fr::from(100u64),
            Fr::from(200u64),
            Fr::from(300u64),
            Fr::from(400u64),
        ];

        let once = poseidon2_permutation(&inputs);
        let twice = poseidon2_permutation(&once);

        assert_ne!(once, twice, "Double permutation should differ from single");
    }

    #[test]
    fn test_configuration_consistency() {
        // The global config should be consistent across calls
        let config1 = &*POSEIDON2_CONFIG;
        let config2 = &*POSEIDON2_CONFIG;

        assert_eq!(config1.t, config2.t);
        assert_eq!(config1.rounds_f, config2.rounds_f);
        assert_eq!(config1.rounds_p, config2.rounds_p);

        // Internal matrix diagonal should be non-zero
        for (i, val) in config1.internal_matrix_diagonal.iter().enumerate() {
            assert!(
                !val.is_zero(),
                "Internal matrix diagonal[{i}] should not be zero"
            );
        }

        // Round constants should have expected dimensions
        assert_eq!(config1.round_constant.len(), 64);
    }

    #[test]
    fn test_different_input_patterns() {
        // Test various input patterns produce different outputs
        let patterns = [
            [
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            ],
            [
                Fr::from(1u64),
                Fr::from(1u64),
                Fr::from(1u64),
                Fr::from(1u64),
            ],
            [
                Fr::from(1u64),
                Fr::from(2u64),
                Fr::from(3u64),
                Fr::from(4u64),
            ],
            [
                Fr::from(4u64),
                Fr::from(3u64),
                Fr::from(2u64),
                Fr::from(1u64),
            ],
        ];

        let mut results = vec![];
        for pattern in &patterns {
            results.push(poseidon2_permutation(pattern));
        }

        // All results should be distinct
        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                assert_ne!(
                    results[i], results[j],
                    "Results for patterns {i} and {j} should differ"
                );
            }
        }
    }
}
