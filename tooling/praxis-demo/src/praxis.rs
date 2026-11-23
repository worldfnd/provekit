//! Core Praxis Witness Encryption (`Setup`, `Enc`, `Dec`, `Comb`) implementing
//! Appendix A (Figures 9 and 10, pp. 46-47) over BN254.

use {
    crate::{
        bqs::Bqs,
        ext::{
            compute_weights_and_cancellations, powers, Cell, FormMatrix, LegKind, RightLeg,
            CROSS_PAIRS,
        },
        params::PraxisParams,
        qap::QapSetup,
        search::{gt_pow_signed, i128_to_fr, search_gt_dlog, Gt, SearchStats},
    },
    anyhow::{ensure, Result},
    ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
    ark_ec::{
        pairing::{Pairing, PairingOutput},
        AffineRepr, CurveGroup, VariableBaseMSM,
    },
    ark_ff::{CyclotomicMultSubgroup, Field, One, PrimeField, Zero},
    ark_serialize::CanonicalSerialize,
    rand::{Rng, RngCore},
    rayon::prelude::*,
    std::time::{Duration, Instant},
};

/// Fast signed-window fixed-base scalar multiplication table for one generator
/// (`G1` or `G2`). Uses `W = 12`-bit signed digits (22 windows of `2^11 = 2048`
/// affine points -> 21 mixed additions per scalar multiplication, zero
/// doublings, ~2.8 MB in `G1` and ~5.7 MB in `G2`).
pub struct FixedBaseTable<G: CurveGroup> {
    /// `windows[w][d]` holds `(d + 1) * 2^{12 * w} * gen` for `d in 0..2048`.
    windows: Vec<Vec<G::Affine>>,
}

const WIN_BITS: usize = 12;
const HALF_WIN: usize = 1 << (WIN_BITS - 1); // 2048
const NUM_WINDOWS: usize = 256usize.div_ceil(WIN_BITS); // 22

impl<G: CurveGroup> FixedBaseTable<G> {
    /// Precompute the signed 12-bit window table for `gen` in parallel.
    pub fn new(gen: G) -> Self {
        let mut bases = Vec::with_capacity(NUM_WINDOWS);
        let mut cur = gen;
        for _ in 0..NUM_WINDOWS {
            bases.push(cur);
            for _ in 0..WIN_BITS {
                cur.double_in_place();
            }
        }

        let windows: Vec<Vec<G::Affine>> = bases
            .into_par_iter()
            .map(|base| {
                let mut proj = Vec::with_capacity(HALF_WIN);
                let mut acc = base;
                for _ in 0..HALF_WIN {
                    proj.push(acc);
                    acc += base;
                }
                G::normalize_batch(&proj)
            })
            .collect();

        Self { windows }
    }

    /// Compute `scalar * gen` in projective coordinates using at most 22 mixed
    /// additions.
    #[inline]
    pub fn mul_scalar(&self, scalar: &Fr) -> G {
        let bigint = scalar.into_bigint();
        let limbs = bigint.as_ref(); // [u64; 4]

        // Extract 12-bit unsigned chunks and convert to signed digits in [-2048, 2047].
        let mut acc = G::zero();
        let mut carry: i32 = 0;
        let mask = ((1u64 << WIN_BITS) - 1) as i32;

        for w in 0..NUM_WINDOWS {
            let bit_pos = w * WIN_BITS;
            let limb_idx = bit_pos / 64;
            let bit_off = bit_pos % 64;
            let mut raw = if limb_idx < 4 {
                limbs[limb_idx] >> bit_off
            } else {
                0
            };
            if bit_off + WIN_BITS > 64 && limb_idx + 1 < 4 {
                raw |= limbs[limb_idx + 1] << (64 - bit_off);
            }
            let mut digit = (raw as i32 & mask) + carry;
            if digit > HALF_WIN as i32 {
                digit -= 1 << WIN_BITS;
                carry = 1;
            } else {
                carry = 0;
            }
            if digit > 0 {
                acc += self.windows[w][(digit - 1) as usize];
            } else if digit < 0 {
                acc -= self.windows[w][((-digit) - 1) as usize];
            }
        }
        debug_assert_eq!(carry, 0);
        acc
    }

    /// Compute `[s * gen]` in affine coordinates for an entire slice of scalars
    /// in parallel.
    pub fn mul_batch_affine(&self, scalars: &[Fr]) -> Vec<G::Affine> {
        let proj: Vec<G> = scalars.par_iter().map(|s| self.mul_scalar(s)).collect();
        G::normalize_batch(&proj)
    }
}

/// Public parameters produced by deterministic `Setup(S)` (Figure 9).
pub struct PublicParams {
    pub params:        PraxisParams,
    pub qap:           QapSetup,
    pub omega:         Fr,
    pub delta_quo:     usize,
    pub delta_rem:     usize,
    /// Indices `k in 0..delta_rem` with `nu \nmid k`.
    pub rem_exponents: Vec<usize>,
}

/// Half of the `G_2` ciphertext (either plain `ct_2` or alpha-scaled
/// `ct_2^alpha`).
#[derive(Debug, Clone)]
pub struct Ct2Sector {
    /// Right factors `H_j^leg in G_2^2`, indexed `[leg_idx * (N + 1) + j]`.
    pub h_factors: Vec<[G2Affine; 2]>,
    /// Search bases `S^leg in G_2`, indexed `[leg_idx]`.
    pub s_bases:   Vec<G2Affine>,
    /// Quotient bases `B_{c, j}^quo`, indexed `[j * num_copies + cell_idx]`.
    pub b_quo:     Vec<G2Affine>,
    /// Remainder bases `B_{c, j}^rem`, indexed `[j * num_copies + cell_idx]`.
    pub b_rem:     Vec<G2Affine>,
    /// Tie bases `B_{a, e}^0`, indexed `[a * (n - 1) + e]` (`a in 0..3, e in
    /// 0..n-1`).
    pub b_tie:     Vec<G2Affine>,
    /// Cross bases `B_{a, e}^iota`, indexed `[pair_idx * (2n - 1) + e]`
    /// (`pair_idx in 0..5`).
    pub b_cross:   Vec<G2Affine>,
}

/// Full Praxis ciphertext `ct = (seed, ct_1, ct_2, ct_2^alpha, K^alpha,
/// m_tilde)` (Figure 9).
#[derive(Debug, Clone)]
pub struct Ciphertext {
    pub seed:       Vec<u8>,
    /// Left factors `F_i^{k1} in G_1^2`, indexed `[k1 * (N + 1) + i]`.
    pub f_factors:  Vec<[G1Affine; 2]>,
    /// Quotient powers `P_k^quo in G_1` (`k in 0..Delta`).
    pub p_quo:      Vec<G1Affine>,
    /// Remainder powers `P_k^rem in G_1` (ordered by `pp.rem_exponents`).
    pub p_rem:      Vec<G1Affine>,
    /// Cancellation column `Y_i in G_1` (`i in 0..=N`).
    pub y_col:      Vec<G1Affine>,
    /// Plain `G_2` elements.
    pub ct2:        Ct2Sector,
    /// Alpha-scaled `G_2` elements.
    pub ct2_alpha:  Ct2Sector,
    /// `K^alpha = [alpha * kappa]_T`.
    pub k_alpha:    Gt,
    /// Masked message `m_tilde = m XOR H_key([kappa]_T)`.
    pub masked_msg: Vec<u8>,
}

impl Ciphertext {
    /// Count of `(G1, G2, GT)` group elements in this ciphertext.
    #[must_use]
    pub fn element_counts(&self) -> (usize, usize, usize) {
        let g1 = self.f_factors.len() * 2 + self.p_quo.len() + self.p_rem.len() + self.y_col.len();
        let g2_one = self.ct2.h_factors.len() * 2
            + self.ct2.s_bases.len()
            + self.ct2.b_quo.len()
            + self.ct2.b_rem.len()
            + self.ct2.b_tie.len()
            + self.ct2.b_cross.len();
        (g1, 2 * g2_one, 1)
    }

    /// Approximate compressed serialized size in bytes (32 B / G1, 64 B / G2,
    /// 384 B / GT).
    #[must_use]
    pub fn compressed_bytes(&self) -> usize {
        let (g1, g2, gt) = self.element_counts();
        g1 * 32 + g2 * 64 + gt * 384 + self.seed.len() + self.masked_msg.len()
    }
}

/// Detailed timings from `Enc`.
#[derive(Debug, Clone)]
pub struct EncTimings {
    pub field_work: Duration,
    pub g1_muls:    Duration,
    pub g2_muls:    Duration,
    pub total:      Duration,
}

/// Detailed timings & search telemetry from `Dec`.
#[derive(Debug, Clone)]
pub struct DecTimings {
    pub forms_and_qap:           Duration,
    pub group_comb_and_pairings: Duration,
    pub search:                  Duration,
    pub total:                   Duration,
    pub search_stats:            SearchStats,
    pub recovered_t:             Option<i128>,
}

/// Deterministic `Setup(S)` (Figure 9). Pads `bqs` if needed to meet Condition
/// (P1) `n <= D`.
pub fn setup(mut bqs: Bqs, params: PraxisParams) -> Result<PublicParams> {
    bqs.pad_for_params(params.n, params.j_rem);
    let qap = QapSetup::setup(bqs)?;
    params.validate(qap.bqs.n_unknowns, qap.d, qap.bqs.constraints.len())?;
    let omega = params.omega()?;

    let delta_quo = qap.d.div_ceil(params.j_quo);
    let delta_rem = (qap.nu * qap.bqs.constraints.len()) / params.j_rem;
    let rem_exponents: Vec<usize> = (0..delta_rem).filter(|k| k % qap.nu != 0).collect();

    Ok(PublicParams {
        params,
        qap,
        omega,
        delta_quo,
        delta_rem,
        rem_exponents,
    })
}

/// Key derivation oracle `H_key([kappa]_T)` using BLAKE3 XOF on canonical
/// serialized `G_T`.
fn hash_key(k_gt: &Gt, msg_len: usize) -> Result<Vec<u8>> {
    let mut ser = Vec::with_capacity(384);
    k_gt.0.serialize_compressed(&mut ser)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"praxis-v1-H_key");
    hasher.update(&ser);
    let mut out = vec![0u8; msg_len];
    hasher.finalize_xof().fill(&mut out);
    Ok(out)
}

/// Centered sampler `D_g` (Definition 5.3, p. 32).
fn sample_centered_r(n_unknowns: usize, g: u64, rng: &mut impl RngCore) -> Vec<i128> {
    let mut r = vec![0i128; n_unknowns + 1];
    let mut sum: i128 = 0;
    for slot in &mut r[1..] {
        let v = rng.random_range(2..=(g + 1)) as i128;
        *slot = v;
        sum += v;
    }
    let r_star = rng.random_range(2..=(g + 1)) as i128;
    let a = ((n_unknowns as i128) * (g as i128 + 1) + 1) / 2;
    r[0] = a + r_star - sum.div_euclid(2);
    r
}

/// Center `c_w` for centered sampler `D_g` (Section 5.2, p. 32).
#[must_use]
pub fn centered_c_w(n_unknowns: usize, g: u64, wt: usize) -> i128 {
    let n = n_unknowns as i128;
    let g_i = g as i128;
    let wt_i = wt as i128;
    let a = (n * (g_i + 1) + 1) / 2;
    let num = (g_i + 3) * (2 + 2 * wt_i - n);
    a + num.div_euclid(4)
}

/// Sample a uniformly random element of `F_q` (512 bits mod `q` -> bias <
/// 2^-256).
fn rand_fr(rng: &mut impl RngCore) -> Fr {
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    Fr::from_le_bytes_mod_order(&buf)
}

/// Sample a uniformly random nonzero element of `F_q^*`.
fn rand_nonzero_fr(rng: &mut impl RngCore) -> Fr {
    loop {
        let x = rand_fr(rng);
        if !x.is_zero() {
            return x;
        }
    }
}

/// Full Praxis `Enc(pp, msg)` (Figure 9, p. 46).
pub fn encrypt(
    pp: &PublicParams,
    msg: &[u8],
    g1_table: &FixedBaseTable<G1Projective>,
    g2_table: &FixedBaseTable<G2Projective>,
    rng: &mut impl RngCore,
) -> Result<(Ciphertext, EncTimings)> {
    let t_total = Instant::now();
    let t_field = Instant::now();

    let p = &pp.params;
    let n_u = pp.qap.bqs.n_unknowns;
    let n_plus_1 = n_u + 1;
    let omega = pp.omega;
    let omega_inv = omega.inverse().expect("omega != 0");

    // Line 1: seed -> M -> Forms(M).
    let mut seed = vec![0u8; p.seed_bytes];
    rng.fill_bytes(&mut seed);
    let form_mat = FormMatrix::from_seed(&seed, p, n_u);

    // Line 2: r <- D_g, y <- F_q^{N+1}, tau <- F_q \ P, Omega_12 <- F_q.
    let r_int = sample_centered_r(n_u, p.g, rng);
    let r_fr: Vec<Fr> = r_int.iter().map(|&v| i128_to_fr(v)).collect();
    let y: Vec<Fr> = (0..n_plus_1).map(|_| rand_fr(rng)).collect();
    let qap_eval = loop {
        let cand = rand_fr(rng);
        if let Ok(eval) = pp.qap.eval_at_tau(cand) {
            break (cand, eval);
        }
    };
    let (tau, qap_tau) = qap_eval;
    let omega12 = rand_fr(rng);

    // Line 3: nonzero coins.
    let omega22 = rand_nonzero_fr(rng);
    let alpha = rand_nonzero_fr(rng);
    let pi = rand_nonzero_fr(rng);
    let s_kind = [
        rand_nonzero_fr(rng), // s_E
        rand_nonzero_fr(rng), // s_O
        rand_nonzero_fr(rng), // s_V
    ];
    let upsilon = rand_nonzero_fr(rng);
    let zeta = rand_nonzero_fr(rng);
    let zeta_p = rand_nonzero_fr(rng);
    let zeta_pp = rand_nonzero_fr(rng);
    let eta = [
        rand_nonzero_fr(rng),
        rand_nonzero_fr(rng),
        rand_nonzero_fr(rng),
    ];

    // Line 4: eps not in {-omega^{-2 k_1}}.
    let omega_neg2 = omega_inv.square();
    let forbidden: Vec<Fr> = powers(omega_neg2, p.k1).into_iter().map(|v| -v).collect();
    let eps = loop {
        let cand = rand_nonzero_fr(rng);
        if !forbidden.contains(&cand) {
            break cand;
        }
    };
    let eps_inv = eps.inverse().expect("eps != 0");
    let omega22_inv = omega22.inverse().expect("omega22 != 0");
    let omega12_over_22 = omega12 * omega22_inv;

    // Line 5: left/right leg scalars & cell scalars gamma_c, key scalar kappa.
    let ups2 = upsilon.square();
    let omega2 = omega.square();
    let ups2_pows = powers(ups2, p.k1);
    let omega2_pows = powers(omega2, p.k1);
    let pi_k1: Vec<Fr> = (0..p.k1)
        .map(|k1| pi * ups2_pows[k1] * (Fr::one() + eps * omega2_pows[k1]))
        .collect();

    let legs = RightLeg::all(p.k2);
    let s_leg: Vec<Fr> = legs
        .iter()
        .map(|leg| s_kind[leg.kind as usize] * upsilon.pow([leg.k_leg(p.k1) as u64]))
        .collect();

    let cells = Cell::all(p.k1, p.k2);
    let gamma_c: Vec<Fr> = cells
        .iter()
        .map(|c| pi_k1[c.k1] * s_leg[c.leg.index(p.k2)])
        .collect();
    let kappa = gamma_c[0] * qap_tau.l_rho_tau;

    // Line 6: z_-, z_o, z_+ in F_q^{N+1}.
    let z_minus = form_mat.eval_z_vector(-upsilon * omega_inv);
    let z_circ = form_mat.eval_z_vector(-upsilon);
    let z_plus = form_mat.eval_z_vector(-omega * upsilon);

    // Precompute combinations used in Line 7.
    let eo_part1: Vec<Fr> = (0..n_plus_1)
        .map(|j| eta[0] * z_circ[j] + eta[1] * z_plus[j])
        .collect();
    let eo_part2: Vec<Fr> = (0..n_plus_1)
        .map(|j| eta[1] * z_minus[j] + eta[2] * z_circ[j])
        .collect();
    let v_part: Vec<Fr> = (0..n_plus_1)
        .map(|j| eta[2] * z_plus[j] - eta[0] * z_minus[j])
        .collect();

    let neg_omega_ups = -omega * upsilon;

    // Line 8: build all G1 scalar exponents.
    let n_f = p.k1 * n_plus_1;
    let n_p_quo = pp.delta_quo;
    let n_p_rem = pp.rem_exponents.len();
    let total_g1 = 2 * n_f + n_p_quo + n_p_rem + n_plus_1;
    let mut g1_scalars = Vec::with_capacity(total_g1);

    // F_i^{k1} * Omega = (pi_{k1} y_i, pi_{k1} (Omega_12 y_i + Omega_22 A_i(tau)))
    for k1 in 0..p.k1 {
        let pk = pi_k1[k1];
        for i in 0..n_plus_1 {
            let f0 = pk * y[i];
            let f1 = pk * (omega12 * y[i] + omega22 * qap_tau.a_tau[i]);
            g1_scalars.push(f0);
            g1_scalars.push(f1);
        }
    }
    // P_k^quo = zeta * tau^k
    let mut cur = zeta;
    for _ in 0..pp.delta_quo {
        g1_scalars.push(cur);
        cur *= tau;
    }
    // P_k^rem = zeta' * tau^k for k in rem_exponents
    let tau_pows_rem = powers(tau, pp.delta_rem);
    for &k in &pp.rem_exponents {
        g1_scalars.push(zeta_p * tau_pows_rem[k]);
    }
    // Y_i = zeta'' * y_i
    for &yi in &y {
        g1_scalars.push(zeta_pp * yi);
    }

    // Build all G2 scalar exponents (plain sector, then alpha-scaled copy).
    let n_h = legs.len() * n_plus_1;
    let n_b_quo = p.j_quo * cells.len();
    let n_b_rem = p.j_rem * cells.len();
    let n_b_tie = 3 * (p.n - 1);
    let n_b_cross = 5 * (2 * p.n - 1);
    let total_g2_one = 2 * n_h + legs.len() + n_b_quo + n_b_rem + n_b_tie + n_b_cross;
    let mut g2_plain = Vec::with_capacity(total_g2_one);

    // H_j^leg under Omega^{-1}:
    //   h1 = s_leg (r_j + A_j(tau)) + vartheta_{leg, j}
    //   h2 = s_leg (B_j(tau) - y_j)
    //   Omega^{-1} * (h1, h2)^T = (h1 - (Omega_12/Omega_22) * h2, h2 / Omega_22)
    for (leg_idx, leg) in legs.iter().enumerate() {
        let sl = s_leg[leg_idx];
        let k_leg = leg.k_leg(p.k1) as u64;
        let u_kleg = upsilon.pow([k_leg]);
        let neg_wu_kleg = neg_omega_ups.pow([k_leg]);
        for j in 0..n_plus_1 {
            let vartheta_j = match leg.kind {
                LegKind::E | LegKind::O => {
                    u_kleg * eo_part1[j] - eps_inv * neg_wu_kleg * eo_part2[j]
                }
                LegKind::V => u_kleg * v_part[j],
            };
            let h1 = sl * (r_fr[j] + qap_tau.a_tau[j]) + vartheta_j;
            let h2 = sl * (qap_tau.b_tau[j] - y[j]);
            g2_plain.push(h1 - omega12_over_22 * h2);
            g2_plain.push(h2 * omega22_inv);
        }
    }
    // S^leg = s_leg
    g2_plain.extend_from_slice(&s_leg);

    // B_{c, j}^quo = gamma_c * Z_c(tau) * tau^{j * Delta} / zeta
    let zeta_inv = zeta.inverse().expect("zeta != 0");
    let tau_delta_quo = tau.pow([pp.delta_quo as u64]);
    let mut chunk_pow = Fr::one();
    for _j in 0..p.j_quo {
        for (c_idx, cell) in cells.iter().enumerate() {
            let zc = if cell.is_key() {
                qap_tau.zp_tau
            } else {
                qap_tau.z_tau
            };
            g2_plain.push(gamma_c[c_idx] * zc * chunk_pow * zeta_inv);
        }
        chunk_pow *= tau_delta_quo;
    }

    // B_{c, j}^rem = gamma_c * Z_0(tau) * tau^{j * Delta'} / zeta'
    let zeta_p_inv = zeta_p.inverse().expect("zeta' != 0");
    let tau_delta_rem = tau.pow([pp.delta_rem as u64]);
    let mut chunk_pow = Fr::one();
    for _j in 0..p.j_rem {
        let factor = qap_tau.z0_tau * chunk_pow * zeta_p_inv;
        for &gc in &gamma_c {
            g2_plain.push(gc * factor);
        }
        chunk_pow *= tau_delta_rem;
    }

    // B_{a, e}^0 = pi * eta_a * P(upsilon) * upsilon^e / zeta''
    let zeta_pp_inv = zeta_pp.inverse().expect("zeta'' != 0");
    let p_upsilon = upsilon.pow([p.n as u64]) - Fr::from(p.c0);
    let ups_pows = powers(upsilon, 2 * p.n - 1);
    for a in 0..3 {
        let base = pi * eta[a] * p_upsilon * zeta_pp_inv;
        for &ue in &ups_pows[..(p.n - 1)] {
            g2_plain.push(base * ue);
        }
    }

    // B_{a, e}^iota = pi * eta_a * eps^iota * upsilon^e / zeta''
    for &(a1, iota) in &CROSS_PAIRS {
        let eps_term = if iota > 0 { eps } else { eps_inv };
        let base = pi * eta[a1 - 1] * eps_term * zeta_pp_inv;
        for &ue in &ups_pows {
            g2_plain.push(base * ue);
        }
    }
    ensure!(g2_plain.len() == total_g2_one);

    // Alpha copies of G2 scalars.
    let mut g2_all = Vec::with_capacity(2 * total_g2_one);
    g2_all.extend_from_slice(&g2_plain);
    g2_all.extend(g2_plain.par_iter().map(|&s| alpha * s).collect::<Vec<_>>());
    let field_work = t_field.elapsed();

    // Line 9: group exponentiations via precomputed fixed-base tables.
    let t_g1 = Instant::now();
    let g1_pts = g1_table.mul_batch_affine(&g1_scalars);
    let g1_muls = t_g1.elapsed();

    let t_g2 = Instant::now();
    let g2_pts = g2_table.mul_batch_affine(&g2_all);
    let g2_muls = t_g2.elapsed();

    // Slice G1 points.
    let mut off = 0usize;
    let mut f_factors = Vec::with_capacity(n_f);
    for idx in 0..n_f {
        f_factors.push([g1_pts[off + 2 * idx], g1_pts[off + 2 * idx + 1]]);
    }
    off += 2 * n_f;
    let p_quo = g1_pts[off..off + n_p_quo].to_vec();
    off += n_p_quo;
    let p_rem = g1_pts[off..off + n_p_rem].to_vec();
    off += n_p_rem;
    let y_col = g1_pts[off..off + n_plus_1].to_vec();

    // Slice G2 points into plain and alpha sectors.
    let slice_sector = |pts: &[G2Affine]| -> Ct2Sector {
        let mut o = 0usize;
        let mut h_factors = Vec::with_capacity(n_h);
        for idx in 0..n_h {
            h_factors.push([pts[o + 2 * idx], pts[o + 2 * idx + 1]]);
        }
        o += 2 * n_h;
        let s_bases = pts[o..o + legs.len()].to_vec();
        o += legs.len();
        let b_quo = pts[o..o + n_b_quo].to_vec();
        o += n_b_quo;
        let b_rem = pts[o..o + n_b_rem].to_vec();
        o += n_b_rem;
        let b_tie = pts[o..o + n_b_tie].to_vec();
        o += n_b_tie;
        let b_cross = pts[o..o + n_b_cross].to_vec();
        Ct2Sector {
            h_factors,
            s_bases,
            b_quo,
            b_rem,
            b_tie,
            b_cross,
        }
    };
    let ct2 = slice_sector(&g2_pts[..total_g2_one]);
    let ct2_alpha = slice_sector(&g2_pts[total_g2_one..]);

    // Line 10: K^alpha = [alpha * kappa]_T and m_tilde = m XOR H_key([kappa]_T).
    let gt_gen = Bn254::pairing(G1Affine::generator(), G2Affine::generator());
    let key_gt = PairingOutput(gt_gen.0.cyclotomic_exp(kappa.into_bigint().as_ref()));
    let k_alpha = PairingOutput(
        gt_gen
            .0
            .cyclotomic_exp((alpha * kappa).into_bigint().as_ref()),
    );
    let pad = hash_key(&key_gt, msg.len())?;
    let masked_msg: Vec<u8> = msg.iter().zip(pad.iter()).map(|(&a, &b)| a ^ b).collect();

    let ct = Ciphertext {
        seed,
        f_factors,
        p_quo,
        p_rem,
        y_col,
        ct2,
        ct2_alpha,
        k_alpha,
        masked_msg,
    };
    let timings = EncTimings {
        field_work,
        g1_muls,
        g2_muls,
        total: t_total.elapsed(),
    };
    Ok((ct, timings))
}

/// Full Praxis `Dec(pp, ct, w)` (Figure 10, p. 47).
/// Returns `Ok((Some(plaintext), timings))` on success, or `Ok((None,
/// timings))` if decryption returns bottom (`\bot`) because `w` is invalid,
/// `xi_key(w) == 0`, or the search fails.
pub fn decrypt(
    pp: &PublicParams,
    ct: &Ciphertext,
    w: &[u8],
    rng: &mut impl RngCore,
) -> Result<(Option<Vec<u8>>, DecTimings)> {
    let t_total = Instant::now();
    let t_qap = Instant::now();

    let p = &pp.params;
    let n_u = pp.qap.bqs.n_unknowns;
    let n_plus_1 = n_u + 1;
    ensure!(
        w.len() == n_plus_1 && w[0] == 1,
        "invalid witness length/w0"
    );

    // Line 1: expand M from seed, compute forms and weights xi_c(w).
    let form_mat = FormMatrix::from_seed(&ct.seed, p, n_u);
    let phi = form_mat.eval_forms_at_witness(w);
    let wc = compute_weights_and_cancellations(&phi, p, pp.omega)?;
    let xi_key = wc.xi[0];

    let empty_stats = SearchStats {
        b_bar:         0,
        baby_steps:    0,
        giant_steps:   0,
        false_fp_hits: 0,
    };

    // Line 2: if xi_key(w) == 0 return \bot.
    if xi_key.is_zero() {
        return Ok((None, DecTimings {
            forms_and_qap:           t_qap.elapsed(),
            group_comb_and_pairings: Duration::ZERO,
            search:                  Duration::ZERO,
            total:                   t_total.elapsed(),
            search_stats:            empty_stats,
            recovered_t:             None,
        }));
    }

    // Line 3: witness polynomials h_key, h_oth, R_w (fails cleanly if w fails any
    // test).
    let Ok(w_polys) = pp.qap.witness_polynomials(w) else {
        return Ok((None, DecTimings {
            forms_and_qap:           t_qap.elapsed(),
            group_comb_and_pairings: Duration::ZERO,
            search:                  Duration::ZERO,
            total:                   t_total.elapsed(),
            search_stats:            empty_stats,
            recovered_t:             None,
        }));
    };
    let forms_and_qap = t_qap.elapsed();

    // Lines 5-7: group additions, MSMs, and multi-pairings.
    let t_comb = Instant::now();
    let ones: Vec<usize> = (0..n_plus_1).filter(|&i| w[i] != 0).collect();

    // Line 5: F_w^{k1} = sum_{i: w_i=1} F_i^{k1}, and Y_w = sum_{i: w_i=1} Y_i.
    let f_w_k1: Vec<[G1Projective; 2]> = (0..p.k1)
        .into_par_iter()
        .map(|k1| {
            let base = k1 * n_plus_1;
            let mut acc0 = G1Projective::zero();
            let mut acc1 = G1Projective::zero();
            for &i in &ones {
                let pair = ct.f_factors[base + i];
                acc0 += pair[0];
                acc1 += pair[1];
            }
            [acc0, acc1]
        })
        .collect();

    let f_w_k1_0_aff =
        G1Projective::normalize_batch(&f_w_k1.iter().map(|p| p[0]).collect::<Vec<_>>());
    let f_w_k1_1_aff =
        G1Projective::normalize_batch(&f_w_k1.iter().map(|p| p[1]).collect::<Vec<_>>());

    let legs = RightLeg::all(p.k2);
    let num_legs = legs.len();

    // F_w^leg = sum_{k1} xi_{(k1, leg)}(w) * F_w^{k1}.
    let f_w_leg: Vec<[G1Affine; 2]> = (0..num_legs)
        .into_par_iter()
        .map(|leg_idx| {
            let scalars = &wc.xi[leg_idx * p.k1..(leg_idx + 1) * p.k1];
            let p0 = G1Projective::msm_unchecked(&f_w_k1_0_aff, scalars).into_affine();
            let p1 = G1Projective::msm_unchecked(&f_w_k1_1_aff, scalars).into_affine();
            [p0, p1]
        })
        .collect();

    let mut y_w_proj = G1Projective::zero();
    for &i in &ones {
        y_w_proj += ct.y_col[i];
    }
    let y_w = y_w_proj.into_affine();

    // Line 6: P_w^{key, j}, P_w^{oth, j}, P_w^{rem, j}.
    let p_key_chunks: Vec<G1Affine> = (0..p.j_quo)
        .into_par_iter()
        .map(|j| {
            let start = j * pp.delta_quo;
            let end = (start + pp.delta_quo).min(w_polys.h_key.len());
            if start >= end {
                return G1Affine::zero();
            }
            G1Projective::msm_unchecked(&ct.p_quo[..end - start], &w_polys.h_key[start..end])
                .into_affine()
        })
        .collect();

    let p_oth_chunks: Vec<G1Affine> = (0..p.j_quo)
        .into_par_iter()
        .map(|j| {
            let start = j * pp.delta_quo;
            let end = (start + pp.delta_quo).min(w_polys.h_oth.len());
            if start >= end {
                return G1Affine::zero();
            }
            G1Projective::msm_unchecked(&ct.p_quo[..end - start], &w_polys.h_oth[start..end])
                .into_affine()
        })
        .collect();

    let p_rem_chunks: Vec<G1Affine> = (0..p.j_rem)
        .into_par_iter()
        .map(|j| {
            let base = j * pp.delta_rem;
            let scalars: Vec<Fr> = pp
                .rem_exponents
                .iter()
                .map(|&k| w_polys.r_w[base + k])
                .collect();
            G1Projective::msm_unchecked(&ct.p_rem, &scalars).into_affine()
        })
        .collect();

    // Flatten cancellation scalars once for both Comb(ct_2) and Comb(ct_2^alpha).
    let mut b_tie_scalars = Vec::with_capacity(3 * (p.n - 1));
    for a in 0..3 {
        b_tie_scalars.extend_from_slice(&wc.x0[a]);
    }
    let mut b_cross_scalars = Vec::with_capacity(5 * (2 * p.n - 1));
    for pair_idx in 0..5 {
        b_cross_scalars.extend_from_slice(&wc.x_cross[pair_idx]);
    }

    let comb = |sector: &Ct2Sector| -> (Gt, Gt) {
        // H_w^leg = sum_{i: w_i=1} H_i^leg.
        let h_w_leg: Vec<[G2Affine; 2]> = (0..num_legs)
            .into_par_iter()
            .map(|leg_idx| {
                let base = leg_idx * n_plus_1;
                let mut acc0 = G2Projective::zero();
                let mut acc1 = G2Projective::zero();
                for &i in &ones {
                    let pair = sector.h_factors[base + i];
                    acc0 += pair[0];
                    acc1 += pair[1];
                }
                [acc0.into_affine(), acc1.into_affine()]
            })
            .collect();

        // B_w = sum x_a^0 B_{a,e}^0 + sum x_a^iota B_{a,e}^iota.
        let b_w = (G2Projective::msm_unchecked(&sector.b_tie, &b_tie_scalars)
            + G2Projective::msm_unchecked(&sector.b_cross, &b_cross_scalars))
        .into_affine();

        // Multi-pairing for Lambda (1 final exponentiation!).
        let num_copies = p.num_copies();
        let mut g1_list = Vec::with_capacity(2 * num_legs + 2 * p.j_quo + p.j_rem + 1);
        let mut g2_list = Vec::with_capacity(2 * num_legs + 2 * p.j_quo + p.j_rem + 1);

        for leg_idx in 0..num_legs {
            g1_list.push(f_w_leg[leg_idx][0]);
            g2_list.push(h_w_leg[leg_idx][0]);
            g1_list.push(f_w_leg[leg_idx][1]);
            g2_list.push(h_w_leg[leg_idx][1]);
        }

        // Subtract key quotient chunks, other quotient chunks, remainder chunks, and
        // (Y_w, B_w).
        for j in 0..p.j_quo {
            let b_key_j = (sector.b_quo[j * num_copies].into_group() * xi_key).into_affine();
            g1_list.push(-p_key_chunks[j]);
            g2_list.push(b_key_j);

            let chunk_bases = &sector.b_quo[j * num_copies + 1..(j + 1) * num_copies];
            let b_oth_j = G2Projective::msm_unchecked(chunk_bases, &wc.xi[1..]).into_affine();
            g1_list.push(-p_oth_chunks[j]);
            g2_list.push(b_oth_j);
        }

        for j in 0..p.j_rem {
            let chunk_bases = &sector.b_rem[j * num_copies..(j + 1) * num_copies];
            let b_rem_j = G2Projective::msm_unchecked(chunk_bases, &wc.xi).into_affine();
            g1_list.push(-p_rem_chunks[j]);
            g2_list.push(b_rem_j);
        }

        g1_list.push(-y_w);
        g2_list.push(b_w);

        let lambda = Bn254::multi_pairing(&g1_list, &g2_list);

        // Multi-pairing for Psi (1 final exponentiation!).
        let psi_g1: Vec<G1Affine> = (0..num_legs).map(|l| f_w_leg[l][0]).collect();
        let psi = Bn254::multi_pairing(&psi_g1, &sector.s_bases);

        (lambda, psi)
    };

    let (lambda, psi) = comb(&ct.ct2);
    let (lambda_alpha, psi_alpha) = comb(&ct.ct2_alpha);

    // Line 8: Lambda' = Lambda^alpha - xi_key * K^alpha - c_w * Psi^alpha
    // (multiplicatively).
    let wt = ones.len() - 1; // number of ones among w_1..w_N (excluding w_0 = 1)
    let c_w = centered_c_w(n_u, p.g, wt);
    let k_alpha_xi = ct.k_alpha.0.cyclotomic_exp(xi_key.into_bigint().as_ref());
    let mut k_alpha_xi_inv = k_alpha_xi;
    k_alpha_xi_inv.conjugate_in_place();
    let psi_alpha_neg_cw = gt_pow_signed(psi_alpha.0, -c_w);
    let lambda_prime = PairingOutput(lambda_alpha.0 * k_alpha_xi_inv * psi_alpha_neg_cw);
    let group_comb_and_pairings = t_comb.elapsed();

    // Line 9: BSGS search for t with |t| <= B and (Psi^alpha)^t == Lambda'.
    let t_search = Instant::now();
    let bound_b = p.search_bound(n_u);
    let expected_abs_t = (p.g as f64) * (((n_u + 4) as f64) / 48.0).sqrt() * 0.797_884_56;
    let (found_t, search_stats) =
        search_gt_dlog(psi_alpha, lambda_prime, bound_b, expected_abs_t, 32, rng);
    let search = t_search.elapsed();

    // Line 10: if no t found return \bot.
    let Some(t) = found_t else {
        return Ok((None, DecTimings {
            forms_and_qap,
            group_comb_and_pairings,
            search,
            total: t_total.elapsed(),
            search_stats,
            recovered_t: None,
        }));
    };

    // Line 11: K = xi_key^{-1} * (Lambda - (c_w + t) * Psi).
    let r_w_total = c_w + t;
    let psi_neg_rw = gt_pow_signed(psi.0, -r_w_total);
    let xi_key_inv = xi_key.inverse().expect("xi_key != 0");
    let key_gt =
        PairingOutput((lambda.0 * psi_neg_rw).cyclotomic_exp(xi_key_inv.into_bigint().as_ref()));

    // Line 12: m = m_tilde XOR H_key(K).
    let pad = hash_key(&key_gt, ct.masked_msg.len())?;
    let plaintext: Vec<u8> = ct
        .masked_msg
        .iter()
        .zip(pad.iter())
        .map(|(&a, &b)| a ^ b)
        .collect();

    Ok((Some(plaintext), DecTimings {
        forms_and_qap,
        group_comb_and_pairings,
        search,
        total: t_total.elapsed(),
        search_stats,
        recovered_t: Some(t),
    }))
}
