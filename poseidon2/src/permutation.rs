/// Poseidon2 permutation for BN254 (t=4).
///
/// Based on the Noir implementation:
/// https://github.com/noir-lang/noir/blob/12ecac9/acvm-repo/bn254_blackbox_solver/src/poseidon2.rs
use {
    crate::constants::{load_diag, load_rc_full1, load_rc_full2, load_rc_partial},
    ark_bn254::Fr,
    ark_ff::Field,
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

/// In-place Poseidon2 permutation over the default BN254 config. Prefer
/// this in hot paths.
#[inline]
pub fn poseidon2_permute_in_place(state: &mut [Fr; 4]) {
    permute_with_config(&POSEIDON2_CONFIG, state);
}

/// Poseidon2 permutation returning a fresh `[Fr; 4]`.
#[inline]
pub fn poseidon2_permutation(inputs: &[Fr; 4]) -> [Fr; 4] {
    let mut state = *inputs;
    poseidon2_permute_in_place(&mut state);
    state
}

// ============================================================================
// Internal primitives — free functions to avoid `&self` dispatch on the hot
// path and to let LLVM inline aggressively even without LTO.
// ============================================================================

#[inline(always)]
fn permute_with_config(config: &Poseidon2Config, state: &mut [Fr; 4]) {
    let rf_first = (config.rounds_f / 2) as usize;
    let p_end = rf_first + config.rounds_p as usize;
    let num_rounds = (config.rounds_f + config.rounds_p) as usize;

    // Initial linear layer.
    ext_mds(state);

    // First rf/2 full rounds.
    for r in 0..rf_first {
        add_round_constants(state, &config.round_constant[r]);
        s_box(state);
        ext_mds(state);
    }

    // Partial rounds: only lane 0 gets the S-box.
    for r in rf_first..p_end {
        state[0] += config.round_constant[r][0];
        state[0] = single_box(state[0]);
        int_mds(state, &config.internal_matrix_diagonal);
    }

    // Last rf/2 full rounds.
    for r in p_end..num_rounds {
        add_round_constants(state, &config.round_constant[r]);
        s_box(state);
        ext_mds(state);
    }
}

/// S-box x → x^5. Uses [`Field::square`] which is ~30% faster than `x * x`.
#[inline(always)]
fn single_box(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// Full-round S-box: x^5 on all four lanes.
#[inline(always)]
fn s_box(state: &mut [Fr; 4]) {
    state[0] = single_box(state[0]);
    state[1] = single_box(state[1]);
    state[2] = single_box(state[2]);
    state[3] = single_box(state[3]);
}

/// Adds the round constants to the state. Explicit unroll so the compiler
/// doesn't need to reason about a 4-iteration zip.
#[inline(always)]
fn add_round_constants(state: &mut [Fr; 4], rc: &[Fr; 4]) {
    state[0] += rc[0];
    state[1] += rc[1];
    state[2] += rc[2];
    state[3] += rc[3];
}

/// External MDS (4×4 matrix multiplication).
///
/// Algorithm taken directly from the Poseidon2 implementation in the
/// Barretenberg crypto module: ~13 additions, zero multiplications.
#[inline(always)]
fn ext_mds(input: &mut [Fr; 4]) {
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

/// Internal MDS: `state[i] = state[i] * diag[i] + sum(state)` for i ∈ 0..4.
/// Partial-round layer; 4 multiplications + 3 additions.
#[inline(always)]
fn int_mds(state: &mut [Fr; 4], diag: &[Fr; 4]) {
    let sum = state[0] + state[1] + state[2] + state[3];
    state[0] = state[0] * diag[0] + sum;
    state[1] = state[1] * diag[1] + sum;
    state[2] = state[2] * diag[2] + sum;
    state[3] = state[3] * diag[3] + sum;
}

#[cfg(test)]
mod tests {
    use {super::*, crate::constants::fe};

    /// Known-answer test: permutation of the all-zero state. Matches the
    /// Barretenberg reference implementation; any divergence means round
    /// constants, matrix layout, or round schedule has drifted.
    #[test]
    fn smoke_test() {
        let result = poseidon2_permutation(&[Fr::zero(); 4]);
        let expected = [
            fe("18DFB8DC9B82229CFF974EFEFC8DF78B1CE96D9D844236B496785C698BC6732E"),
            fe("095C230D1D37A246E8D2D5A63B165FE0FADE040D442F61E25F0590E5FB76F839"),
            fe("0BB9545846E1AFA4FA3C97414A60A20FC4949F537A68CCECA34C5CE71E28AA59"),
            fe("18A4F34C9C6F99335FF7638B82AEED9018026618358873C982BBDDE265B2ED6D"),
        ];
        assert_eq!(result, expected);
    }

    /// Avalanche property: flipping a single bit of input must change every
    /// output lane (not merely the output as a whole).
    #[test]
    fn single_bit_avalanche() {
        let zeros = [Fr::zero(); 4];
        let mut one_bit = zeros;
        one_bit[0] = Fr::from(1u64);

        let a = poseidon2_permutation(&zeros);
        let b = poseidon2_permutation(&one_bit);

        for i in 0..4 {
            assert_ne!(a[i], b[i], "lane {i}");
        }
    }
}
