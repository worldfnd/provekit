//! `#[ignore]` prover profiling harness.
//!
//! Two probes (run with `--release`):
//!
//! ```text
//! # Size sweep: BF vs EF vs bn254 at 2^14..2^20
//! cargo test -p provekit-fixtures --release --test profile size_sweep -- --ignored --nocapture
//!
//! # Flamegraph + stage breakdown for one 2^20 goldilocks-BF prove
//! cargo test -p provekit-fixtures --release --test profile flamegraph_2pow20_bf -- --ignored --nocapture
//! ```

use {
    ark_std::rand::distributions::{Distribution, Standard},
    provekit_common::{
        Base, Ext, FieldHash, HashConfig, PublicInputs, PublicInputsHash, WhirR1CSProof,
        WhirR1CSScheme, R1CS,
    },
    provekit_fixtures::builders::squaring_chain,
    provekit_prover::WhirR1CSProver,
    provekit_verifier::WhirR1CSVerifier,
    std::{
        collections::HashMap,
        path::PathBuf,
        time::{Duration, Instant},
    },
    whir::transcript::ProverState,
};

/// Log2 witness sizes to sweep.
const SIZES: [u32; 4] = [14, 16, 18, 20];

/// Instance-binding hash for the probes (matches the harness default).
const HASH: HashConfig = HashConfig::Sha256;

/// Inputs for a single-commit prove, built outside the timer so scheme
/// construction and the `commit`/`prove_noir` ownership copies aren't measured.
struct ProveInputs<P: FieldHash> {
    scheme:          WhirR1CSScheme<P>,
    r1cs_owned:      R1CS<Base<P>>,
    witness_commit:  Vec<Base<P>>,
    witness_prove:   Vec<Base<P>>,
    num_witnesses:   usize,
    num_constraints: usize,
}

/// Build the scheme + ownership copies (excluded from the timer and
/// flamegraph).
fn prove_setup<P>(r1cs: &R1CS<Base<P>>, witness: &[Base<P>]) -> ProveInputs<P>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let scheme = WhirR1CSScheme::<P>::new_for_r1cs(r1cs, witness.len(), 0, Vec::new(), true, HASH);
    ProveInputs {
        scheme,
        r1cs_owned: r1cs.clone(),
        witness_commit: witness.to_vec(),
        witness_prove: witness.to_vec(),
        num_witnesses: r1cs.num_witnesses(),
        num_constraints: r1cs.num_constraints(),
    }
}

/// Time the proving core — `commit` + `prove_noir` — from pre-built inputs.
fn time_prove_core<P>(
    inp: ProveInputs<P>,
    public_inputs: &PublicInputs<Base<P>>,
) -> (Duration, WhirR1CSProof, WhirR1CSScheme<P>)
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let ProveInputs {
        scheme,
        r1cs_owned,
        witness_commit,
        witness_prove,
        num_witnesses,
        num_constraints,
    } = inp;

    // Transcript binding derives from the scheme; built before the timer starts.
    let instance = public_inputs.hash_bytes::<P>(HASH);
    let ds = scheme.create_domain_separator().instance(&instance);

    let start = Instant::now();
    let mut merlin = ProverState::new(&ds, P::transcript_sponge(HASH));
    let commitment = scheme
        .commit(
            &mut merlin,
            num_witnesses,
            num_constraints,
            witness_commit,
            true,
        )
        .expect("commit");
    let proof = scheme
        .prove_noir(
            merlin,
            r1cs_owned,
            vec![commitment],
            witness_prove,
            public_inputs,
        )
        .expect("prove_noir");
    (start.elapsed(), proof, scheme)
}

/// Build a `2^log_size`-witness squaring chain, prove, verify, and return
/// `(prove, verify, narg_bytes, hints_bytes)`.
fn run_one<P>(log_size: u32) -> (Duration, Duration, usize, usize)
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let depth = (1usize << log_size) - 2; // num_witnesses = depth + 2 = 2^log_size
    let (r1cs, w) = squaring_chain::<Base<P>>(2, depth);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);

    // Only commit + prove_noir are timed (setup excluded above).
    let inp = prove_setup::<P>(&r1cs, &w);
    let (prove_t, proof, scheme) = time_prove_core::<P>(inp, &public_inputs);

    let t = Instant::now();
    scheme
        .verify(&proof, &public_inputs, &r1cs)
        .expect("verify");
    let verify_t = t.elapsed();

    (
        prove_t,
        verify_t,
        proof.narg_string.len(),
        proof.hints.len(),
    )
}

/// Run one (field, size) cell and print its row immediately (so partial results
/// survive a later OOM). Wrapped in `catch_unwind` so a panic in one cell does
/// not abort the rest of the sweep.
fn row<P>(label: &str, log_size: u32)
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let res = std::panic::catch_unwind(|| run_one::<P>(log_size));
    match res {
        Ok((p, v, narg, hints)) => println!(
            "{:>5} | {:<13} | {:>10.3?} | {:>9.3?} | {:>8} | {:>9}",
            format!("2^{log_size}"),
            label,
            p,
            v,
            narg,
            hints
        ),
        Err(_) => println!(
            "{:>5} | {:<13} | {:>10} | {:>9} | {:>8} | {:>9}",
            format!("2^{log_size}"),
            label,
            "FAILED",
            "-",
            "-",
            "-"
        ),
    }
}

#[test]
#[ignore = "profiling probe; run --release -- --ignored --nocapture"]
fn size_sweep() {
    provekit_backend_goldilocks::register();
    provekit_backend_bn254::register();

    println!("\n size | field         |      prove |    verify |     narg |     hints");
    println!("------+---------------+------------+-----------+----------+----------");
    for &s in &SIZES {
        row::<provekit_backend_goldilocks::GoldilocksField>("goldilocks-BF", s);
    }
    for &s in &SIZES {
        row::<provekit_backend_goldilocks::GoldilocksEfField>("goldilocks-EF", s);
    }
    for &s in &SIZES {
        row::<provekit_backend_bn254::Bn254Field>("bn254", s);
    }
    println!();
}

/// Repo `provekit/.claude/profile/` directory (created if absent).
fn profile_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("provekit")
        .join(".claude")
        .join("profile");
    std::fs::create_dir_all(&dir).expect("create profile dir");
    dir
}

#[test]
#[ignore = "profiling probe; run --release -- --ignored --nocapture"]
fn flamegraph_2pow20_bf() {
    use {
        tracing_flame::FlameLayer,
        tracing_subscriber::{prelude::*, registry::Registry},
    };

    provekit_backend_goldilocks::register();

    let dir = profile_dir();
    let folded_path = dir.join("goldilocks_bf_2pow20.folded");
    let svg_path = dir.join("goldilocks_bf_2pow20.svg");

    // Fixture-gen + prove setup happen BEFORE the flame layer installs, so only
    // the prove core (commit + prove_noir) is captured.
    let log_size = 20u32;
    let depth = (1usize << log_size) - 2;
    let (r1cs, w) = squaring_chain::<Base<provekit_backend_goldilocks::GoldilocksField>>(2, depth);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    let inp = prove_setup::<provekit_backend_goldilocks::GoldilocksField>(&r1cs, &w);

    // Global subscriber required: prove() uses rayon, and only the global
    // default captures spans created on rayon worker threads.
    let (flame_layer, guard) =
        FlameLayer::with_file(&folded_path).expect("create flame layer file");
    let subscriber = Registry::default().with(flame_layer);
    tracing::subscriber::set_global_default(subscriber).expect("set global subscriber");

    // Timed + captured: the true prove core only (setup/clones already done).
    let (prove_t, proof, _scheme) =
        time_prove_core::<provekit_backend_goldilocks::GoldilocksField>(inp, &public_inputs);
    println!(
        "\n[flamegraph] 2^20 goldilocks-BF prove={prove_t:.3?} narg={} hints={}",
        proof.narg_string.len(),
        proof.hints.len()
    );

    // Flush folded stacks.
    drop(guard);

    // Render SVG via inferno.
    let folded = std::fs::read_to_string(&folded_path).expect("read folded");
    {
        let svg = std::fs::File::create(&svg_path).expect("create svg");
        let mut opts = inferno::flamegraph::Options::default();
        opts.title = "provekit 2^20 goldilocks-BF prove".to_string();
        inferno::flamegraph::from_reader(&mut opts, folded.as_bytes(), svg)
            .expect("render flamegraph");
    }

    println!("[flamegraph] folded: {}", folded_path.display());
    println!("[flamegraph] svg:    {}", svg_path.display());

    analyze_folded(&folded);
}

/// Parse tracing-flame folded stacks and print (1) per-leaf self-time table and
/// (2) the top folded stacks by total weight.
fn analyze_folded(folded: &str) {
    // Each line: `frame1;frame2;...;leaf weight`. In folded format the weight is
    // the self-time of that exact stack, so summing by leaf gives per-span self
    // time, and aggregating identical stacks gives total stack time.
    let mut leaf_self: HashMap<&str, u64> = HashMap::new();
    let mut stack_total: HashMap<&str, u64> = HashMap::new();
    let mut total: u64 = 0;

    for line in folded.lines() {
        let Some((stack, weight_str)) = line.rsplit_once(' ') else {
            continue;
        };
        let Ok(weight) = weight_str.trim().parse::<u64>() else {
            continue;
        };
        total += weight;
        *stack_total.entry(stack).or_default() += weight;
        let leaf = stack.rsplit(';').next().unwrap_or(stack);
        *leaf_self.entry(leaf).or_default() += weight;
    }

    if total == 0 {
        println!("[flamegraph] no folded samples captured");
        return;
    }
    let pct = |w: u64| 100.0 * (w as f64) / (total as f64);

    let mut leaves: Vec<(&str, u64)> = leaf_self.into_iter().collect();
    leaves.sort_by_key(|leaf| std::cmp::Reverse(leaf.1));
    println!("\n=== 2^20 goldilocks-BF: per-span SELF time (top 25) ===");
    println!("   self% |       weight | span");
    for (leaf, w) in leaves.iter().take(25) {
        println!("  {:>5.1}% | {:>12} | {}", pct(*w), w, leaf);
    }

    let mut stacks: Vec<(&str, u64)> = stack_total.into_iter().collect();
    stacks.sort_by_key(|stack| std::cmp::Reverse(stack.1));
    println!("\n=== 2^20 goldilocks-BF: top 20 folded stacks by total time ===");
    for (stack, w) in stacks.iter().take(20) {
        println!("  {:>5.1}% | {:>12} | {}", pct(*w), w, stack);
    }
    println!("\n[flamegraph] total folded weight = {total}");
}
