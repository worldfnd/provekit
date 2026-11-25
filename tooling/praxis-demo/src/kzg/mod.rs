//! KZG mode (`--mode kzg`): Pure-Rust BN254 **2-Round Spartan + HyperKZG**
//! backend for ProveKit + Praxis Witness Encryption.
//!
//! Replaces WHIR with a universal-SRS multilinear KZG PCS (**HyperKZG** over
//! BN254 univariate KZG) so that:
//! - Any ProveKit Noir circuit — including 2-round multi-challenge passport
//!   circuits (`t_attest`, `t_add_*`, `complete_age_check`) — is proved and
//!   verified in **exactly 2 BN254 pairings** with **zero Groth16, zero
//!   per-circuit setup, and zero Go/gnark**.
//! - Encrypting Praxis to this succinct 2-pairing verifier keeps the 100-bit
//!   Praxis ciphertext around **~7.5–9 GiB** (comparable to Praxis's 7.88 GiB
//!   Groth16 benchmark) instead of 100 GiB–5.6 TiB under direct BQS!

pub mod bqs_cost;
pub mod hyperkzg;
pub mod spartan;
pub mod univariate;

use {
    crate::{
        direct::name_to_input_map,
        kzg::{
            bqs_cost::{build_algebraic_verifier_bqs, estimate_full_kzg_verifier_bqs},
            spartan::{prove, verify, SpartanKzgCircuit},
            univariate::KzgSrs,
        },
        load_or_compile_noir,
        params::PraxisParams,
        praxis::{decrypt, encrypt, setup, FixedBaseTable},
    },
    anyhow::{ensure, Context, Result},
    ark_bn254::{G1Projective, G2Projective},
    ark_ec::PrimeGroup,
    ark_ff::One,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    rand::rng,
    std::{path::Path, time::Instant},
};

/// Run the end-to-end **KZG** (`Spartan + HyperKZG` -> Praxis) demo on any
/// ProveKit Noir circuit (works on `praxis-satoshi`, `t_attest`,
/// `complete_age_check`, etc.).
pub fn run(
    circuit_path: &Path,
    input_override: Option<&Path>,
    message: &str,
    name_override: Option<&str>,
) -> Result<()> {
    let params = PraxisParams::table4_100bit();
    let msg_bytes = message.as_bytes();
    ensure!(
        msg_bytes.len() <= params.msg_bytes,
        "message too long ({} bytes, max {})",
        msg_bytes.len(),
        params.msg_bytes
    );
    let mut msg_padded = vec![0u8; params.msg_bytes];
    msg_padded[..msg_bytes.len()].copy_from_slice(msg_bytes);

    println!("==================================================================");
    println!("  Praxis Witness Encryption + ProveKit Demo  [mode: KZG]");
    println!("  Backend  : Pure-Rust 2-Round Spartan + HyperKZG (BN254, 2 pairings)");
    println!("  Security : {}", params.name);
    println!("  Threads  : {}", rayon::current_num_threads());
    println!("==================================================================\n");

    // 1. Compile / load Noir circuit -> ProveKit R1CS + GE opt + 2-layer split.
    let t0 = Instant::now();
    let program = load_or_compile_noir(circuit_path)?;
    let circuit = SpartanKzgCircuit::prepare(program)?;
    let w2_size = circuit
        .r1cs
        .num_witnesses()
        .saturating_sub(circuit.split_builders.w1_size);
    println!(
        "[1] Noir -> ProveKit R1CS + 2-Layer Split ({:.2?}):",
        t0.elapsed()
    );
    println!(
        "    {} constraints (m_0={}), {} real witnesses (w1={} [m_w1={}], w2={} [m_w2={}]), {} \
         pub inputs, {} challenges",
        circuit.r1cs.num_constraints(),
        circuit.m_0,
        circuit.r1cs.num_witnesses(),
        circuit.split_builders.w1_size,
        circuit.m_w1,
        w2_size,
        circuit.m_w2,
        circuit.r1cs.num_public_inputs,
        circuit.challenge_offsets.len()
    );

    // 2. Universal Powers-of-Tau SRS setup (one-time, shared by ALL circuits up
    //    to max_len).
    let t_tbl = Instant::now();
    let g1_table = FixedBaseTable::new(G1Projective::generator());
    let g2_table = FixedBaseTable::new(G2Projective::generator());
    let mut rng = rng();
    let srs_len = circuit.required_srs_len();
    let (srs, srs_time) = KzgSrs::setup_with_table(srs_len, &g1_table, &mut rng)?;
    println!(
        "[2] Universal BN254 KZG SRS (N = 2^{} = {}): {:.2?} (tables: {:.2?})",
        srs_len.ilog2(),
        srs_len,
        srs_time,
        t_tbl.elapsed() - srs_time
    );

    // 3. Load inputs and generate a real 2-round Spartan + HyperKZG proof!
    let input_map = if let Some(name) = name_override {
        println!("\n[3] Proving with CLI --name=\"{}\"...", name);
        name_to_input_map(name)?
    } else {
        let default_input = circuit_path.join("Prover.toml");
        let input_path = input_override.unwrap_or(&default_input);
        println!(
            "\n[3] Proving with Spartan + HyperKZG from {}...",
            input_path.display()
        );
        let (map, _ret) = read_inputs_from_file(input_path, &circuit.program.abi)
            .with_context(|| format!("reading inputs from {}", input_path.display()))?;
        map
    };

    let (proof, prove_t) = prove(&circuit, &srs, &input_map)?;
    println!(
        "    Prove time: {:.2?} (exec+solve: {:.2?}, KZG commit: {:.2?}, sumchecks: {:.2?}, \
         HyperKZG open: {:.2?})",
        prove_t.total,
        prove_t.noir_exec_and_solve,
        prove_t.kzg_commit,
        prove_t.sumchecks,
        prove_t.hyperkzg_open
    );
    println!(
        "    Proof size: {:.2} KiB ({} bytes), final pairings: {}",
        proof.compressed_bytes() as f64 / 1024.0,
        proof.compressed_bytes(),
        proof.num_pairings()
    );

    // 4. Verify the Spartan + HyperKZG proof in 2 BN254 pairings (+ tamper test).
    let (vdata, verify_t) = verify(&circuit, &srs, &proof)?;
    println!(
        "[4] Native Spartan + HyperKZG Verify: VALID in {:.2?} (sumchecks+R1CS: {:.2?}, {} \
         pairings: {:.2?})",
        verify_t.total, verify_t.sumchecks_and_r1cs, verify_t.num_pairings, verify_t.kzg_pairings
    );

    let mut bad_proof = proof.clone();
    bad_proof.eval_w1_at_r1 += ark_bn254::Fr::one();
    ensure!(
        verify(&circuit, &srs, &bad_proof).is_err(),
        "SECURITY BUG: tampered Spartan+HyperKZG proof should fail verification!"
    );
    println!("    Tamper check: REJECTED cleanly (modified w1(r1))");

    // 5. Report full succinct Spartan + HyperKZG (+ SPARK) -> Praxis 100-bit BQS
    //    cost breakdown.
    let est = estimate_full_kzg_verifier_bqs(
        circuit.m_0,
        circuit.m_w1,
        circuit.m_w2,
        circuit.is_dual_mode(),
    );
    println!("\n[5] Full Succinct Verifier -> Praxis 100-bit WE Projection (no Groth16/gnark):");
    println!(
        "    Breakdown : 2-pairing = {}b, G1 MSMs = {}b, sumchecks+SPARK = {}b, Skyscraper FS = \
         {}b",
        est.n_two_pairing, est.n_g1_msms, est.n_sumchecks, est.n_transcript
    );
    println!(
        "    Total BQS : N = {} Boolean unknowns, n_c = {} (F_max <= 2047)",
        est.n_total, est.n_constraints
    );
    println!(
        "    Praxis WE : CT = {:.2} GiB, Enc ~ {:.1}s, BSGS Search ~ {:.1}s ({:.2} GiB RAM)",
        est.ct_gib, est.enc_sec, est.dec_search_sec, est.table_gib
    );
    println!("    (Compare  : Praxis paper Groth16 3-pairing verifier = 7.88 GiB, N = 391,693)");

    // 6. Live 100-bit Praxis WE round-trip over the proof's executable algebraic
    //    verifier BQS (outer + inner sumcheck & HyperKZG folding checks)!
    println!(
        "\n[6] Live 100-bit Praxis Enc/Dec on proof's algebraic verifier core (\"{}\"):",
        message
    );
    let (alg_bqs, alg_w_bits) = build_algebraic_verifier_bqs(&circuit, &proof, &vdata)?;
    ensure!(
        alg_bqs.is_satisfied(&alg_w_bits)?,
        "algebraic verifier BQS must be satisfied by valid Spartan+HyperKZG proof"
    );
    let raw_nc = alg_bqs.constraints.len();
    let pp = setup(alg_bqs, params.clone())?;
    let (ct, enc_t) = encrypt(&pp, &msg_padded, &g1_table, &g2_table, &mut rng)?;
    let (n_g1, n_g2, n_gt) = ct.element_counts();
    println!(
        "    Core BQS  : N = {} bits ({} constraints), CT = {:.2} MiB ({} G1, {} G2, {} GT)",
        pp.qap.bqs.n_unknowns,
        raw_nc,
        ct.compressed_bytes() as f64 / (1024.0 * 1024.0),
        n_g1,
        n_g2,
        n_gt
    );
    println!("    Enc time  : {:.2?}", enc_t.total);

    let (dec_opt, dec_t) = decrypt(&pp, &ct, &alg_w_bits, &mut rng)?;
    println!(
        "    Dec time  : {:.2?} (forms+QAP: {:.2?}, MSMs+pairings: {:.2?}, BSGS: {:.2?})",
        dec_t.total, dec_t.forms_and_qap, dec_t.group_comb_and_pairings, dec_t.search
    );
    let pt = dec_opt.context("Praxis decryption failed on valid Spartan+HyperKZG witness!")?;
    ensure!(pt == msg_padded, "decrypted plaintext mismatch!");
    let trimmed: Vec<u8> = pt.iter().copied().take_while(|&b| b != 0).collect();
    let recovered = String::from_utf8_lossy(&trimmed);
    println!("    Decrypted : \"{}\"  -> SUCCESS (exact match!)", recovered);

    // Negative check: flip 1 bit in the proof witness -> Praxis rejects <bottom>.
    let mut bad_w = alg_w_bits.clone();
    bad_w[1] ^= 1;
    let (bad_dec, bad_t) = decrypt(&pp, &ct, &bad_w, &mut rng)?;
    ensure!(
        bad_dec.is_none(),
        "SECURITY BUG: tampered proof witness should never decrypt!"
    );
    println!(
        "    Negative  : tampered proof witness REJECTED (<bottom>) in {:.2?}",
        bad_t.total
    );

    Ok(())
}
