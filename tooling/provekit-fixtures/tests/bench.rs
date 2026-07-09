//! Proving-time benchmarks over `complete_age_check`-sized synthetic R1CS.
//!
//! Prover cost is structural, so a same-size synthetic instance proxies real
//! proving time. These are `#[ignore]`d; run manually with `--nocapture`
//! (and `--release` for the full size) and read the printed durations.

use {
    provekit_backend_bn254::{register, Bn254Field, FieldElement},
    provekit_fixtures::{
        builders::{satisfies, sized_r1cs},
        harness::time_dual_commit_prove,
    },
};

/// `complete_age_check`: 711,664 constraints · 1,247,227 witnesses · w1 ≈ 50%
/// (m = 20) · 118 challenges · ~3.55M non-zeros · 0 public inputs.
const AGE_CHECK_WITNESSES: usize = 1_247_227;
const AGE_CHECK_CONSTRAINTS: usize = 711_664;
const AGE_CHECK_W1: usize = 620_627;
const AGE_CHECK_CHALLENGES: usize = 118;

/// The same shape at m ≈ 16 — a fast smoke for the dual-commit path.
const SCALED_WITNESSES: usize = 90_000;
const SCALED_CONSTRAINTS: usize = 51_000;
const SCALED_W1: usize = 45_000;

fn run_sized_bench(
    label: &str,
    witnesses: usize,
    constraints: usize,
    w1: usize,
    challenges: usize,
) {
    register();
    let (r1cs, w) = sized_r1cs::<FieldElement>(witnesses, constraints, 0x0a6e_c4ec);
    assert!(
        satisfies(&r1cs, &w),
        "[{label}] generated R1CS must be satisfiable"
    );
    let nnz = r1cs.a().iter().count() + r1cs.b().iter().count() + r1cs.c().iter().count();
    let dur = time_dual_commit_prove::<Bn254Field>(&r1cs, w, w1, challenges).expect("prove");
    println!(
        "[{label}] witnesses={} constraints={} w1={w1} challenges={challenges} nnz={nnz} \
         prove={dur:?}",
        r1cs.num_witnesses(),
        r1cs.num_constraints(),
    );
}

#[test]
#[ignore = "scaled (m~16) smoke for the dual-commit benchmark path; run with --nocapture"]
fn bench_age_check_sized_scaled() {
    run_sized_bench(
        "scaled",
        SCALED_WITNESSES,
        SCALED_CONSTRAINTS,
        SCALED_W1,
        AGE_CHECK_CHALLENGES,
    );
}

#[test]
#[ignore = "full complete_age_check-sized proving-time benchmark; run --release --nocapture"]
fn bench_age_check_sized_full() {
    run_sized_bench(
        "age-check",
        AGE_CHECK_WITNESSES,
        AGE_CHECK_CONSTRAINTS,
        AGE_CHECK_W1,
        AGE_CHECK_CHALLENGES,
    );
}
