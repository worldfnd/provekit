//! Concrete Praxis parameters (Section 6.2, Table 4) on BN254.

use {
    anyhow::{ensure, Result},
    ark_bn254::Fr,
    ark_ff::{Field, PrimeField},
};

/// Parameters of an instantiation of Praxis over BN254's scalar field `Fr`.
#[derive(Debug, Clone)]
pub struct PraxisParams {
    /// Human-readable name (e.g. `"100-bit (Table 4)"`).
    pub name:       &'static str,
    /// Security level lambda in bits.
    pub lambda:     usize,
    /// Message length in bytes (mu / 8). Paper Table 4 uses 100 bits; Lean uses
    /// 256 bits.
    pub msg_bytes:  usize,
    /// Seed length in bytes for `H_seed`.
    pub seed_bytes: usize,
    /// Degree `d_R` of the cyclotomic ring `R_q = F_q[Y]/(Y^{d_R} + 1)` (power
    /// of two).
    pub d_r:        usize,
    /// Number of rows `k` of the MSIS matrix `M`.
    pub k:          usize,
    /// Extension degree `n = (k + 1) * d_R`, even and dividing `q - 1`.
    pub n:          usize,
    /// Non-residue `c_0` such that `P(T) = T^n - c_0` is irreducible over
    /// `F_q`.
    pub c0:         u64,
    /// Shared factor grid row count `K_1` (left legs).
    pub k1:         usize,
    /// Shared factor grid column group count `K_2` (3 * K_2 right legs; K_1 *
    /// K_2 = n / 2).
    pub k2:         usize,
    /// Secret integer range `g` (each `r_i` uniform on `{2, ..., g + 1}`).
    pub g:          u64,
    /// Number of quotient chunks `J`.
    pub j_quo:      usize,
    /// Number of remainder chunks `J'`.
    pub j_rem:      usize,
}

impl PraxisParams {
    /// Exact 100-bit security parameters from Table 4 (Section 6.2) of the
    /// Praxis paper, with 256-bit messages & seeds (matching `praxis-lean`,
    /// Section 6.4) and `J = J' = 1` (optimal for small circuits where `D ~
    /// n`; chunking only saves when `D >> n`).
    #[must_use]
    pub fn table4_100bit() -> Self {
        Self {
            name:       "100-bit security (Praxis Table 4 on BN254)",
            lambda:     100,
            msg_bytes:  32,
            seed_bytes: 32,
            d_r:        64,
            k:          71,
            n:          4608,
            c0:         5,
            k1:         192,
            k2:         12,
            g:          1_736_375_024_658_487,
            j_quo:      1,
            j_rem:      1,
        }
    }

    /// Tiny parameters for fast unit tests (Example 5.2 / Figure 5: `n = 4, K_1
    /// = 2, K_2 = 1`).
    #[cfg(test)]
    #[must_use]
    pub fn tiny_test() -> Self {
        Self {
            name:       "tiny-test (n=4, g=64)",
            lambda:     8,
            msg_bytes:  32,
            seed_bytes: 32,
            d_r:        2,
            k:          1,
            n:          4,
            c0:         5,
            k1:         2,
            k2:         1,
            g:          64,
            j_quo:      1,
            j_rem:      1,
        }
    }

    /// Primitive `n`-th root of unity `omega = c_0^((q - 1) / n)` in `F_q`.
    pub fn omega(&self) -> Result<Fr> {
        let mut qm1_limbs = Fr::MODULUS.0;
        qm1_limbs[0] -= 1; // q is an odd prime
                           // Divide 256-bit integer `q - 1` by `n` using big-endian schoolbook division.
        let n_u128 = self.n as u128;
        let mut rem: u128 = 0;
        let mut quot = [0u64; 4];
        for i in (0..4).rev() {
            let cur = (rem << 64) | (qm1_limbs[i] as u128);
            quot[i] = (cur / n_u128) as u64;
            rem = cur % n_u128;
        }
        ensure!(rem == 0, "n = {} must divide q - 1", self.n);
        let omega = Fr::from(self.c0).pow(quot);
        ensure!(omega.pow([self.n as u64]) == Fr::from(1u64), "omega^n != 1");
        ensure!(
            omega.pow([(self.n / 2) as u64]) == -Fr::from(1u64),
            "omega^(n/2) != -1 (c0 may not be a non-residue)"
        );
        Ok(omega)
    }

    /// Check structural & Section 5.4 admissibility invariants for a system of
    /// `n_unknowns` and `d_points` evaluation points.
    pub fn validate(&self, n_unknowns: usize, d_points: usize, n_constraints: usize) -> Result<()> {
        ensure!(self.d_r.is_power_of_two(), "d_r must be a power of two");
        ensure!(
            self.n == (self.k + 1) * self.d_r,
            "n must equal (k + 1) * d_r"
        );
        ensure!(self.n % 2 == 0, "n must be even");
        ensure!(self.k1 * self.k2 == self.n / 2, "K1 * K2 must equal n / 2");
        ensure!(
            self.n <= d_points,
            "Condition (P1) violated: n ({}) must be <= D ({})",
            self.n,
            d_points
        );
        if n_constraints > 0 {
            ensure!(
                n_constraints % self.j_rem == 0,
                "J' ({}) must divide n_c ({})",
                self.j_rem,
                n_constraints
            );
        }
        let _ = self.omega()?;
        let search_bound: u128 = (n_unknowns as u128 + 1) * (self.g as u128 + 1);
        ensure!(
            search_bound < (1u128 << 120),
            "search bound B = {} unexpectedly huge",
            search_bound
        );
        Ok(())
    }

    /// Number of MSIS columns `ell = ceil(N / d_R)`.
    #[must_use]
    pub fn ell(&self, n_unknowns: usize) -> usize {
        n_unknowns.div_ceil(self.d_r).max(1)
    }

    /// Total number of table copies `3 * n / 2`.
    #[must_use]
    pub fn num_copies(&self) -> usize {
        3 * self.n / 2
    }

    /// Search bound `B = (N + 1) * (g + 1)`.
    #[must_use]
    pub fn search_bound(&self, n_unknowns: usize) -> i128 {
        (n_unknowns as i128 + 1) * (self.g as i128 + 1)
    }
}
