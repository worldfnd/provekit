//! Fast parallel BSGS search in BN254's `G_T` using the degree-12 palindromic
//! `F_p` linear recurrence (6 muls + 11 adds per candidate, Section 5.2 &
//! [LV00]) and a bucketed 64-bit fingerprint table.

use {
    ark_bn254::{Bn254, Fq, Fq12, Fq6, Fr},
    ark_ec::pairing::PairingOutput,
    ark_ff::{AdditiveGroup, CyclotomicMultSubgroup, Field, One, PrimeField, Zero},
    rand::RngCore,
    rayon::prelude::*,
    std::sync::atomic::{AtomicBool, Ordering},
};

/// BN254 `G_T` element (multiplicative `Fq12`, written additively in the
/// paper).
pub type Gt = PairingOutput<Bn254>;

/// Random `F_p`-linear functional `ell: F_{p^6} -> F_p` used to produce 64-bit
/// fingerprints of `G_T` sign classes `{V, V^{-1}}` (Section 5.2, p. 32).
#[derive(Debug, Clone, Copy)]
struct SignClassLinearForm {
    rho: [Fq; 6],
}

impl SignClassLinearForm {
    fn random(rng: &mut impl RngCore) -> Self {
        let mut rho = [Fq::zero(); 6];
        for r in &mut rho {
            let mut buf = [0u8; 64];
            rng.fill_bytes(&mut buf);
            *r = Fq::from_le_bytes_mod_order(&buf);
        }
        Self { rho }
    }

    /// Evaluate `ell(V.c0)` where `V.c0 in F_{p^6}` is the shared `F_{p^6}`
    /// part of `{V, V^{-1}}`.
    #[inline]
    fn eval(&self, v: &Fq12) -> Fq {
        let c = &v.c0;
        self.rho[0] * c.c0.c0
            + self.rho[1] * c.c0.c1
            + self.rho[2] * c.c1.c0
            + self.rho[3] * c.c1.c1
            + self.rho[4] * c.c2.c0
            + self.rho[5] * c.c2.c1
    }
}

/// Zero-cost 64-bit fingerprint of a canonical `Fq` element (low 64 bits of its
/// unique Montgomery representation — avoids Montgomery reduction in the hot
/// loop).
#[inline]
fn fp64(y: Fq) -> u64 {
    y.0 .0[0]
}

/// Degree-12 palindromic linear recurrence coefficients `d_1, ..., d_6 in F_p`
/// for stepping by a fixed generator `g in G_T`:
/// `y_{k+6} = d_1 (y_{k+5} + y_{k-5}) + d_2 (y_{k+4} + y_{k-4}) + d_3 (y_{k+3}
/// + y_{k-3})` `        + d_4 (y_{k+2} + y_{k-2}) + d_5 (y_{k+1} + y_{k-1}) +
/// d_6 y_k - y_{k-6}` Costs exactly **6 multiplications and 11
/// additions/subtractions in `F_p`**.
#[derive(Debug, Clone, Copy)]
pub struct PalindromicRecurrence {
    pub d: [Fq; 6],
}

impl PalindromicRecurrence {
    /// Derive the exact recurrence coefficients for `g in G_T subset
    /// F_{p^12}^*`. Because `g^{p^6} = g^{-1}`, its 12 conjugates over
    /// `F_p` pair into 6 reciprocal pairs `{g^{p^i}, g^{-p^i}}` whose sums
    /// `r_i = 2 * (g^{p^i}).c0 in F_{p^6}` have a degree-6 monic polynomial
    /// `Q(Y) = prod_{i=0..5} (Y - r_i) in F_p[Y]`.
    pub fn from_generator(g: Fq12) -> Self {
        let mut roots = [Fq6::zero(); 6];
        let mut cur = g;
        for slot in &mut roots {
            let mut r = cur.c0;
            r.double_in_place();
            *slot = r;
            cur.frobenius_map_in_place(1);
        }

        // Compute Q(Y) = prod_{i=0..5} (Y - roots[i]) = Y^6 + e_1 Y^5 + ... + e_6.
        // Stored as poly[deg] = coeff of Y^deg.
        let mut poly = [Fq6::zero(); 7];
        poly[0] = Fq6::one();
        for (deg, &r) in roots.iter().enumerate() {
            for j in (0..=deg).rev() {
                let prev = poly[j];
                poly[j + 1] += prev;
                poly[j] = -(prev * r);
            }
        }

        // Extract e_1..e_6 in F_p (sanity-check all non-base coordinates vanish).
        let extract_fp = |x: Fq6| -> Fq {
            debug_assert!(x.c0.c1.is_zero() && x.c1.is_zero() && x.c2.is_zero());
            x.c0.c0
        };
        let e1 = extract_fp(poly[5]);
        let e2 = extract_fp(poly[4]);
        let e3 = extract_fp(poly[3]);
        let e4 = extract_fp(poly[2]);
        let e5 = extract_fp(poly[1]);
        let e6 = extract_fp(poly[0]);

        // Expand P_g(X) = X^6 * Q(X + X^{-1}) = X^12 + c_1 X^11 + ... + c_6 X^6 + ... +
        // 1.
        let c1 = e1;
        let c2 = e2 + Fq::from(6u64);
        let c3 = e3 + Fq::from(5u64) * e1;
        let c4 = e4 + Fq::from(4u64) * e2 + Fq::from(15u64);
        let c5 = e5 + Fq::from(3u64) * e3 + Fq::from(10u64) * e1;
        let c6 = e6 + Fq::from(2u64) * e4 + Fq::from(6u64) * e2 + Fq::from(20u64);

        Self {
            d: [-c1, -c2, -c3, -c4, -c5, -c6],
        }
    }

    /// Compute next element `y_{k+6}` from the 12 previous values `[y_{k-6},
    /// ..., y_{k+5}]`.
    #[inline(always)]
    pub fn step(&self, w: &[Fq; 12]) -> Fq {
        let mut s = self.d[0] * (w[11] + w[1]);
        s += self.d[1] * (w[10] + w[2]);
        s += self.d[2] * (w[9] + w[3]);
        s += self.d[3] * (w[8] + w[4]);
        s += self.d[4] * (w[7] + w[5]);
        s += self.d[5] * w[6];
        s - w[0]
    }
}

/// Entry in the bucketed baby-step fingerprint table: 12 bytes (`u64` fp +
/// `u32` baby index).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct BabyEntry {
    fp:  u64,
    idx: u32,
}

/// Statistics returned by the BSGS search for demo telemetry.
#[derive(Debug, Clone, Copy)]
pub struct SearchStats {
    pub b_bar:         usize,
    pub baby_steps:    u64,
    pub giant_steps:   u64,
    pub false_fp_hits: u64,
}

/// Signed scalar exponentiation `base^exp` in `G_T` (`exp in i128`).
pub fn gt_pow_signed(base: Fq12, exp: i128) -> Fq12 {
    if exp == 0 {
        return Fq12::one();
    }
    let abs = exp.unsigned_abs();
    let limbs = [abs as u64, (abs >> 64) as u64];
    let res = base.cyclotomic_exp(limbs);
    if exp < 0 {
        let mut conj = res;
        conj.conjugate_in_place();
        conj
    } else {
        res
    }
}

/// Outward BSGS search for the integer `t` of least absolute value with `|t| <=
/// max_abs_t` satisfying `base^t == target` in BN254's `G_T` (Line 9 of Figure
/// 10 & Section 5.2).
///
/// `expected_abs_t` tunes the baby-step table size `b_bar` (optimal `~
/// sqrt(E[|t|])`).
pub fn search_gt_dlog(
    base: Gt,
    target: Gt,
    max_abs_t: i128,
    expected_abs_t: f64,
    max_giant_rounds: usize,
    rng: &mut impl RngCore,
) -> (Option<i128>, SearchStats) {
    let g = base.0;
    let h = target.0;

    if h.is_one() {
        return (Some(0), SearchStats {
            b_bar:         0,
            baby_steps:    0,
            giant_steps:   0,
            false_fp_hits: 0,
        });
    }
    if g.is_one() {
        return (None, SearchStats {
            b_bar:         0,
            baby_steps:    0,
            giant_steps:   0,
            false_fp_hits: 0,
        });
    }

    // Choose b_bar near sqrt(E[|t|]), capped at 2^25 (~402 MB table) and >= 32.
    let raw_b = expected_abs_t.sqrt().ceil() as usize;
    let max_b_for_bound = (max_abs_t.min(1 << 25) as usize).max(1);
    let b_bar = raw_b.clamp(32, 1 << 25).min(max_b_for_bound.max(32));

    let lf = SignClassLinearForm::random(rng);
    let baby_rec = PalindromicRecurrence::from_generator(g);

    // Choose bucket prefix bits so average bucket size is ~4..8 entries.
    let bucket_bits: u32 = if b_bar >= (1 << 22) {
        22
    } else if b_bar >= (1 << 16) {
        16
    } else if b_bar >= (1 << 10) {
        10
    } else {
        6
    };
    let num_buckets = 1usize << bucket_bits;
    let bucket_shift = 64 - bucket_bits;

    // 1. Compute all `b_bar` baby-step 64-bit fingerprints in parallel via the
    //    6-mul recurrence.
    let num_threads = rayon::current_num_threads().max(1);
    let chunk_size = b_bar.div_ceil(num_threads).max(64);
    let mut baby_fps = vec![0u64; b_bar];

    baby_fps
        .par_chunks_mut(chunk_size)
        .enumerate()
        .for_each(|(chunk_idx, slice)| {
            let start = chunk_idx * chunk_size;
            let len = slice.len();
            if len == 0 {
                return;
            }
            let init_count = len.min(12);
            let mut cur = gt_pow_signed(g, start as i128);
            let mut ring = [Fq::zero(); 12];
            for i in 0..init_count {
                let y = lf.eval(&cur);
                ring[i] = y;
                slice[i] = fp64(y);
                if i + 1 < init_count {
                    cur *= g;
                }
            }
            if len <= 12 {
                return;
            }
            // Advance using the 6-mul palindromic recurrence.
            for slot in &mut slice[12..] {
                let next = baby_rec.step(&ring);
                *slot = fp64(next);
                ring.copy_within(1..12, 0);
                ring[11] = next;
            }
        });

    // 2. Build flat radix-bucketed baby-step table (directory + entries).
    let mut counts = vec![0u32; num_buckets];
    for &fp in &baby_fps {
        counts[(fp >> bucket_shift) as usize] += 1;
    }
    let mut offsets = vec![0u32; num_buckets + 1];
    let mut running = 0u32;
    for b in 0..num_buckets {
        offsets[b] = running;
        running += counts[b];
    }
    offsets[num_buckets] = running;

    let mut cursor = offsets[..num_buckets].to_vec();
    let mut table = vec![BabyEntry { fp: 0, idx: 0 }; b_bar];
    for (idx, &fp) in baby_fps.iter().enumerate() {
        let bucket = (fp >> bucket_shift) as usize;
        let pos = cursor[bucket] as usize;
        table[pos] = BabyEntry {
            fp,
            idx: idx as u32,
        };
        cursor[bucket] = (pos + 1) as u32;
    }
    drop(baby_fps);
    drop(cursor);
    drop(counts);

    // 3. Giant steps: stride M = 2 * b_bar - 1, searching j = 0, +-1, +-2, ... in
    //    growing rounds.
    let stride = (2 * b_bar - 1) as i128;
    let giant_g_pos = gt_pow_signed(g, -stride); // stepping by -M tests positive t ~ j*M +- b
    let mut giant_g_neg = giant_g_pos;
    giant_g_neg.conjugate_in_place(); // stepping by +M tests negative t ~ -k*M +- b
    let giant_rec = PalindromicRecurrence::from_generator(giant_g_pos);

    let max_j = ((max_abs_t + b_bar as i128) / stride + 1) as usize;
    let mut total_giant_steps = 0u64;
    let mut false_hits = 0u64;

    // Search j in outward rounds: first round covers |j| <= initial_span, then
    // doubles.
    let mut j_lo = 0usize;
    let mut span = (b_bar / 4).max(64);
    let mut round = 0usize;

    while j_lo <= max_j && round < max_giant_rounds {
        let j_hi = (j_lo + span).min(max_j + 1);
        let round_len = j_hi - j_lo;

        // Search both signs (+j and -j for j in j_lo..j_hi) in parallel.
        let found = AtomicBool::new(false);
        let jobs_per_sign = num_threads.max(1);
        let sub_len = round_len.div_ceil(jobs_per_sign).max(16);

        // Build list of (is_neg_branch, start_j, end_j) tasks.
        let mut tasks = Vec::new();
        for &neg_branch in &[false, true] {
            let mut s = if neg_branch && j_lo == 0 { 1 } else { j_lo };
            while s < j_hi {
                let e = (s + sub_len).min(j_hi);
                tasks.push((neg_branch, s, e));
                s = e;
            }
        }

        let results: Vec<(Option<i128>, u64, u64)> = tasks
            .into_par_iter()
            .map(|(neg_branch, start_j, end_j)| {
                let step_elem = if neg_branch { giant_g_neg } else { giant_g_pos };
                let len = end_j - start_j;
                let mut local_false = 0u64;
                let mut local_steps = 0u64;

                let probe = |fp: u64, j_abs: usize, local_false: &mut u64| -> Option<i128> {
                    let bucket = (fp >> bucket_shift) as usize;
                    let lo = offsets[bucket] as usize;
                    let hi = offsets[bucket + 1] as usize;
                    for entry in &table[lo..hi] {
                        let e_fp = entry.fp;
                        if e_fp == fp {
                            let b = entry.idx as i128;
                            let j_signed = if neg_branch {
                                -(j_abs as i128)
                            } else {
                                j_abs as i128
                            };
                            let base_t = j_signed * stride;
                            for cand in [base_t + b, base_t - b] {
                                if cand.abs() <= max_abs_t && gt_pow_signed(g, cand) == h {
                                    return Some(cand);
                                }
                            }
                            *local_false += 1;
                        }
                    }
                    None
                };

                let init_count = len.min(12);
                let mut cur = h * gt_pow_signed(step_elem, start_j as i128);
                let mut ring = [Fq::zero(); 12];
                for i in 0..init_count {
                    if found.load(Ordering::Relaxed) {
                        return (None, local_steps, local_false);
                    }
                    let y = lf.eval(&cur);
                    ring[i] = y;
                    local_steps += 1;
                    if let Some(t) = probe(fp64(y), start_j + i, &mut local_false) {
                        found.store(true, Ordering::Relaxed);
                        return (Some(t), local_steps, local_false);
                    }
                    if i + 1 < init_count {
                        cur *= step_elem;
                    }
                }
                if len <= 12 {
                    return (None, local_steps, local_false);
                }

                for offset in 12..len {
                    // Amortize atomic check every 1024 steps.
                    if (offset & 1023) == 0 && found.load(Ordering::Relaxed) {
                        return (None, local_steps, local_false);
                    }
                    let next = giant_rec.step(&ring);
                    local_steps += 1;
                    if let Some(t) = probe(fp64(next), start_j + offset, &mut local_false) {
                        found.store(true, Ordering::Relaxed);
                        return (Some(t), local_steps, local_false);
                    }
                    ring.copy_within(1..12, 0);
                    ring[11] = next;
                }
                (None, local_steps, local_false)
            })
            .collect();

        let mut best: Option<i128> = None;
        for (hit, steps, fh) in results {
            total_giant_steps += steps;
            false_hits += fh;
            if let Some(t) = hit {
                best = match best {
                    None => Some(t),
                    Some(prev) if t.abs() < prev.abs() => Some(t),
                    Some(prev) => Some(prev),
                };
            }
        }
        if let Some(t) = best {
            return (Some(t), SearchStats {
                b_bar,
                baby_steps: b_bar as u64,
                giant_steps: total_giant_steps,
                false_fp_hits: false_hits,
            });
        }

        j_lo = j_hi;
        span = span.saturating_mul(2);
        round += 1;
    }

    (None, SearchStats {
        b_bar,
        baby_steps: b_bar as u64,
        giant_steps: total_giant_steps,
        false_fp_hits: false_hits,
    })
}

/// Convert a small signed integer `t` into `Fr`.
#[must_use]
pub fn i128_to_fr(x: i128) -> Fr {
    let abs = Fr::from(x.unsigned_abs());
    if x < 0 {
        -abs
    } else {
        abs
    }
}
