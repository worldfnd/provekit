//! Field-generic builders for synthetic R1CS instances and their witnesses.
//!
//! Every builder returns `(R1CS<F>, Vec<F>)` — a constraint system and a
//! satisfying full witness (the constant `1` at index 0, public inputs next) —
//! using only `R1CS::add_constraint`, so it works for any field without a
//! circuit compiler. All instances are plain-arithmetic (`num_challenges = 0`).

use {
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
