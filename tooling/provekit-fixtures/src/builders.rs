//! Field-generic builders for synthetic R1CS instances and their witnesses.
//!
//! Most builders return `(R1CS<F>, Vec<F>)` — a constraint system and a
//! satisfying full witness (the constant `1` at index 0, public inputs next) —
//! using only `R1CS::add_constraint`, so they work for any field without a
//! circuit compiler. These instances are plain-arithmetic (`num_challenges =
//! 0`). The exceptions are the challenge-bearing builders ([`logup_lookup`],
//! [`multi_challenge_inverses`]), which leave the challenge-dependent `w2` to a
//! paired `*_w2` completion.

use {
    anyhow::{ensure, Context, Result},
    ark_ff::Field,
    ark_std::rand::{rngs::StdRng, Rng, SeedableRng},
    provekit_common::R1CS,
};

/// Checks `(A·w) * (B·w) = C·w` for every constraint row.
#[must_use]
pub fn satisfies<F: Field>(r1cs: &R1CS<F>, w: &[F]) -> bool {
    (0..r1cs.num_constraints()).all(|row| {
        let a = r1cs
            .a()
            .iter_row(row)
            .fold(F::zero(), |acc, (col, v)| acc + v * w[col]);
        let b = r1cs
            .b()
            .iter_row(row)
            .fold(F::zero(), |acc, (col, v)| acc + v * w[col]);
        let c = r1cs
            .c()
            .iter_row(row)
            .fold(F::zero(), |acc, (col, v)| acc + v * w[col]);
        a * b == c
    })
}

/// `w[i]^2 = w[i+1]` chain: `depth` constraints, `depth + 2` witnesses, the
/// input `x` exposed as a single public input. `depth` is the size knob —
/// `depth + 2 > 2^13` crosses the WHIR witness-domain floor.
#[must_use]
pub fn squaring_chain<F: Field>(x: u64, depth: usize) -> (R1CS<F>, Vec<F>) {
    let mut r1cs = R1CS::<F>::new();
    r1cs.add_witnesses(depth + 2);
    r1cs.num_public_inputs = 1;
    let one = F::one();
    let mut w = vec![one, F::from(x)];
    for i in 1..=depth {
        r1cs.add_constraint(&[(one, i)], &[(one, i)], &[(one, i + 1)]);
        let sq = w[i] * w[i];
        w.push(sq);
    }
    (r1cs, w)
}

/// `p0 * p1 = z` with two public inputs — exercises the public-input binding
/// loop at `N ≥ 2`, unreachable with a single input.
#[must_use]
pub fn two_public_inputs<F: Field>(p0: u64, p1: u64) -> (R1CS<F>, Vec<F>) {
    let mut r1cs = R1CS::<F>::new();
    r1cs.add_witnesses(4);
    r1cs.num_public_inputs = 2;
    let one = F::one();
    r1cs.add_constraint(&[(one, 1)], &[(one, 2)], &[(one, 3)]);
    let (a, b) = (F::from(p0), F::from(p1));
    let w = vec![one, a, b, a * b];
    (r1cs, w)
}

/// `count` random `(coeff, col)` terms over `[0, cols)` (`count` may be 0).
fn random_terms<F: Field>(rng: &mut StdRng, cols: usize, count: usize) -> Vec<(F, usize)> {
    (0..count)
        .map(|_| {
            let coeff = F::from(rng.gen_range(1u64..=7));
            let col = rng.gen_range(0..cols);
            (coeff, col)
        })
        .collect()
}

/// A random 1–3 term linear combination.
fn random_lc<F: Field>(rng: &mut StdRng, cols: usize) -> Vec<(F, usize)> {
    let count = rng.gen_range(1..=3usize.min(cols));
    random_terms(rng, cols, count)
}

/// `Σ coeff·w[col]` (duplicate columns sum, matching `add_constraint`).
fn eval_lc<F: Field>(terms: &[(F, usize)], w: &[F]) -> F {
    terms
        .iter()
        .fold(F::zero(), |acc, &(coeff, col)| acc + coeff * w[col])
}

/// `num_gates` multiply gates over `num_inputs` random inputs, satisfiable by
/// construction (each gate's output holds `(A·w)·(B·w)`). The first input is
/// exposed as the single public input.
///
/// # Panics
/// Panics if `num_inputs == 0` (there would be no input to expose as public).
#[must_use]
pub fn random_satisfiable<F: Field>(
    seed: u64,
    num_inputs: usize,
    num_gates: usize,
) -> (R1CS<F>, Vec<F>) {
    assert!(
        num_inputs >= 1,
        "need at least one input to expose as public"
    );
    let mut rng = StdRng::seed_from_u64(seed);
    let mut r1cs = R1CS::<F>::new();
    let total = 1 + num_inputs + num_gates;
    r1cs.add_witnesses(total);
    r1cs.num_public_inputs = 1;
    let one = F::one();

    let mut w = Vec::with_capacity(total);
    w.push(one);
    for _ in 0..num_inputs {
        w.push(F::rand(&mut rng));
    }
    for g in 0..num_gates {
        let out = 1 + num_inputs + g; // == current w.len()
        let a_row = random_lc::<F>(&mut rng, out);
        let b_row = random_lc::<F>(&mut rng, out);
        let product = eval_lc(&a_row, &w) * eval_lc(&b_row, &w);
        w.push(product);
        r1cs.add_constraint(&a_row, &b_row, &[(one, out)]);
    }
    (r1cs, w)
}

/// Satisfiable synthetic R1CS of a target size and density, proxying a real
/// circuit's structural prover cost: ~2.5 / 1 / 1.5 non-zeros per A / B / C
/// row, no public inputs. Inputs use `F::from(u64)` (not random field
/// elements), so the constraint structure is identical across fields for a
/// given seed.
///
/// # Panics
/// Panics if `num_witnesses <= num_constraints + 1` (no room for inputs).
#[must_use]
pub fn sized_r1cs<F: Field>(
    num_witnesses: usize,
    num_constraints: usize,
    seed: u64,
) -> (R1CS<F>, Vec<F>) {
    assert!(
        num_witnesses > num_constraints + 1,
        "need room for input witnesses"
    );
    let num_inputs = num_witnesses - num_constraints - 1;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut r1cs = R1CS::<F>::new();
    r1cs.add_witnesses(num_witnesses);
    r1cs.num_public_inputs = 0;
    r1cs.reserve_constraints(num_constraints, num_constraints * 5);
    let one = F::one();

    let mut w = Vec::with_capacity(num_witnesses);
    w.push(one);
    for _ in 0..num_inputs {
        w.push(F::from(rng.gen::<u64>()));
    }
    for g in 0..num_constraints {
        let out = 1 + num_inputs + g; // == current w.len()
        let na = rng.gen_range(1..=4usize); // A ~2.5/row
        let a_row = random_terms::<F>(&mut rng, out, na);
        let b_row = random_terms::<F>(&mut rng, out, 1); // B 1/row
        let nc = rng.gen_range(0..=1usize); // C ~1.5/row
        let extra = random_terms::<F>(&mut rng, out, nc);
        // Choose the output witness so C·w = out + Σ(extra·w) == (A·w)·(B·w).
        let out_val = eval_lc(&a_row, &w) * eval_lc(&b_row, &w) - eval_lc(&extra, &w);
        w.push(out_val);
        let mut c_row = vec![(one, out)];
        c_row.extend(extra);
        r1cs.add_constraint(&a_row, &b_row, &c_row);
    }
    (r1cs, w)
}

// --- challenge-bearing (dual-commitment) builders ---
//
// These return the circuit and `w1`/`w2` split, not a full witness: the `w2`
// tail depends on the Fiat-Shamir challenge and is filled by a paired `*_w2`
// completion at prove time.

/// A LogUp lookup argument: prove every looked-up value is in the table with
/// the right multiplicity. For a random `c`, LogUp checks
/// `Σ_i 1/(c - a_i) = Σ_j m_j/(c - t_j)` (`a_i` lookups, `t_j` table, `m_j`
/// multiplicities), encoded as:
/// 1. `(c - a_i) · ainv_i = 1`
/// 2. `(c - t_j) · tinv_j = 1`
/// 3. `m_j · tinv_j = mt_j`
/// 4. `Σ_i ainv_i - Σ_j mt_j = 0`
///
/// Layout (split at `w1_size = 1 + 2·N + M`):
/// `w1 = [one, t_0..t_{N-1}, a_0..a_{M-1}, m_0..m_{N-1}]`,
/// `w2 = [c, ainv_0..ainv_{M-1}, tinv_0..tinv_{N-1}, mt_0..mt_{N-1}]`.
/// Pair with [`logup_lookup_w2`].
#[derive(Debug, Clone)]
pub struct LogUpInstance<F: Field> {
    /// The lookup constraint system.
    pub r1cs:              R1CS<F>,
    /// Pre-challenge witness (table, lookups, multiplicities); its length is
    /// the w1/w2 split.
    pub w1:                Vec<F>,
    /// Challenge positions within `w2`.
    pub challenge_offsets: Vec<usize>,
    /// Number of table entries `N`.
    pub table_len:         usize,
    /// Number of lookups `M`.
    pub lookup_len:        usize,
}

/// Start indices of the table, lookups, and multiplicities in the
/// [`logup_lookup`] `w1` layout.
const fn logup_w1_bases(table_len: usize, lookup_len: usize) -> (usize, usize, usize) {
    (1, 1 + table_len, 1 + table_len + lookup_len)
}

/// Build a satisfiable LogUp instance with `table_len` table entries and
/// `lookup_len` lookups drawn (seeded) from the table. Table values are
/// `0..table_len`; multiplicities are the realized lookup counts.
///
/// # Panics
/// Panics if `table_len == 0` or `lookup_len == 0`.
#[must_use]
pub fn logup_lookup<F: Field>(table_len: usize, lookup_len: usize, seed: u64) -> LogUpInstance<F> {
    assert!(table_len >= 1, "need at least one table entry");
    assert!(lookup_len >= 1, "need at least one lookup");
    let (n, m) = (table_len, lookup_len);
    let mut rng = StdRng::seed_from_u64(seed);
    let one = F::one();

    // Pick lookups from the table and tally multiplicities.
    let mut counts = vec![0u64; n];
    let mut lookups = Vec::with_capacity(m);
    for _ in 0..m {
        let j = rng.gen_range(0..n);
        counts[j] += 1;
        lookups.push(j);
    }

    // w1 = [one, table, lookups, multiplicities].
    let mut w1 = Vec::with_capacity(1 + 2 * n + m);
    w1.push(one);
    for j in 0..n {
        w1.push(F::from(j as u64));
    }
    for &j in &lookups {
        w1.push(F::from(j as u64));
    }
    for &count in &counts {
        w1.push(F::from(count));
    }
    let w1_size = 1 + 2 * n + m;

    // Witness-index bases.
    let (t0, a0, m0) = logup_w1_bases(n, m);
    let c_idx = w1_size;
    let (ainv0, tinv0, mt0) = (c_idx + 1, c_idx + 1 + m, c_idx + 1 + m + n);

    let mut r1cs = R1CS::<F>::new();
    r1cs.add_witnesses(2 + 4 * n + 2 * m);
    r1cs.num_public_inputs = 0;

    // 1. (c - a_i) · ainv_i = 1
    for i in 0..m {
        r1cs.add_constraint(&[(one, c_idx), (-one, a0 + i)], &[(one, ainv0 + i)], &[(
            one, 0,
        )]);
    }
    // 2. (c - t_j) · tinv_j = 1
    for j in 0..n {
        r1cs.add_constraint(&[(one, c_idx), (-one, t0 + j)], &[(one, tinv0 + j)], &[(
            one, 0,
        )]);
    }
    // 3. m_j · tinv_j = mt_j
    for j in 0..n {
        r1cs.add_constraint(&[(one, m0 + j)], &[(one, tinv0 + j)], &[(one, mt0 + j)]);
    }
    // 4. Σ_i ainv_i - Σ_j mt_j = 0  (encoded as `(…) · 1 = 0`)
    let mut sum_row = Vec::with_capacity(m + n);
    sum_row.extend((0..m).map(|i| (one, ainv0 + i)));
    sum_row.extend((0..n).map(|j| (-one, mt0 + j)));
    r1cs.add_constraint(&sum_row, &[(one, 0)], &[]);

    LogUpInstance {
        r1cs,
        w1,
        challenge_offsets: vec![0],
        table_len: n,
        lookup_len: m,
    }
}

/// `w2` for [`logup_lookup`]:
/// `[c, ainv_0..ainv_{M-1}, tinv_0..tinv_{N-1}, mt_0..mt_{N-1}]` with
/// `ainv_i = 1/(c - a_i)`, `tinv_j = 1/(c - t_j)`, `mt_j = m_j · tinv_j`.
/// `table_len`/`lookup_len` must match the [`logup_lookup`] instance.
pub fn logup_lookup_w2<F: Field>(
    challenges: &[F],
    w1: &[F],
    table_len: usize,
    lookup_len: usize,
) -> Result<Vec<F>> {
    ensure!(!challenges.is_empty(), "expected one challenge");
    let (n, m) = (table_len, lookup_len);
    ensure!(
        w1.len() == 1 + 2 * n + m,
        "w1 length {} does not match table_len {n} / lookup_len {m}",
        w1.len(),
    );
    let c = challenges[0];
    let (t0, a0, m0) = logup_w1_bases(n, m);

    let mut w2 = Vec::with_capacity(1 + m + 2 * n);
    w2.push(c); // c at w2[0]

    // ainv_i = 1/(c - a_i)
    for i in 0..m {
        let denom = c - w1[a0 + i];
        ensure!(!denom.is_zero(), "challenge collides with a lookup value");
        w2.push(
            denom
                .inverse()
                .context("nonzero denominator is invertible")?,
        );
    }
    // tinv_j = 1/(c - t_j)
    let mut tinv = Vec::with_capacity(n);
    for j in 0..n {
        let denom = c - w1[t0 + j];
        ensure!(!denom.is_zero(), "challenge collides with a table value");
        tinv.push(
            denom
                .inverse()
                .context("nonzero denominator is invertible")?,
        );
    }
    w2.extend_from_slice(&tinv);
    // mt_j = m_j · tinv_j
    for j in 0..n {
        w2.push(w1[m0 + j] * tinv[j]);
    }
    Ok(w2)
}

/// `k` independent inverse constraints `c_i · inv_i = 1`, each `c_i` a distinct
/// challenge — covers challenge binding with multiple offsets.
///
/// Layout `[one | c_0, inv_0, c_1, inv_1, …]`, split at `w1_size = 1`; `c_i` at
/// `w2` offset `2·i`. Pair with [`multi_challenge_inverses_w2`].
///
/// # Panics
/// Panics if `num_challenges == 0`.
#[must_use]
pub fn multi_challenge_inverses<F: Field>(num_challenges: usize) -> (R1CS<F>, Vec<F>, Vec<usize>) {
    assert!(num_challenges >= 1, "need at least one challenge");
    let k = num_challenges;
    let mut r1cs = R1CS::<F>::new();
    r1cs.add_witnesses(1 + 2 * k); // [one, (c_i, inv_i) × k]
    r1cs.num_public_inputs = 0;
    let one = F::one();
    // c_i · inv_i = 1
    for i in 0..k {
        r1cs.add_constraint(&[(one, 1 + 2 * i)], &[(one, 2 + 2 * i)], &[(one, 0)]);
    }
    let challenge_offsets = (0..k).map(|i| 2 * i).collect(); // c_i at w2 offset 2i
    (r1cs, vec![one], challenge_offsets)
}

/// `w2` for [`multi_challenge_inverses`]: `[c_0, 1/c_0, c_1, 1/c_1, …]`.
pub fn multi_challenge_inverses_w2<F: Field>(challenges: &[F], _w1: &[F]) -> Result<Vec<F>> {
    let mut w2 = Vec::with_capacity(2 * challenges.len());
    for &c in challenges {
        ensure!(!c.is_zero(), "drawn challenge is zero; cannot invert");
        w2.push(c);
        w2.push(c.inverse().context("nonzero challenge has an inverse")?);
    }
    Ok(w2)
}

/// A dual-commitment instance that *also* carries a public input, so a single
/// proof must satisfy both the challenge binding and the public-input binding
/// (`witness[1] == public_inputs[0]`). The public value `p` lives in `w1` (the
/// public weight binds the `w1` commitment), and a single challenge `c` is
/// pinned by `c · (1/c) = 1`.
///
/// Layout `[one, p | c, inv]`, split at `w1_size = 2`; `c` at `w2` offset `0`.
/// Pair with [`multi_challenge_inverses_w2`] (`k = 1` → `[c, 1/c]`). Returns
/// `(r1cs, w1, challenge_offsets)`. Set `public_inputs = [p]`.
#[must_use]
pub fn challenge_with_public_input<F: Field>(p: u64) -> (R1CS<F>, Vec<F>, Vec<usize>) {
    let mut r1cs = R1CS::<F>::new();
    r1cs.add_witnesses(4); // [one, p, c, inv]
    r1cs.num_public_inputs = 1;
    let one = F::one();
    // p · 1 = p — binds the public witness (index 1) into the constraint system.
    r1cs.add_constraint(&[(one, 1)], &[(one, 0)], &[(one, 1)]);
    // c · inv = 1 — challenge binding (c at index 2 = w2[0], inv at index 3).
    r1cs.add_constraint(&[(one, 2)], &[(one, 3)], &[(one, 0)]);
    (r1cs, vec![one, F::from(p)], vec![0])
}
