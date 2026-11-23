//! Praxis 100-bit Witness Encryption + ProveKit Noir Demo ("satoshi" name
//! check).
//!
//! Compiles a real Noir circuit (`noir-examples/praxis-satoshi`) via ProveKit's
//! R1CS compiler, converts its R1CS into a Boolean Quadratic System (BQS),
//! encrypts a secret message under **full 100-bit Praxis parameters** (Table 4
//! on BN254), and decrypts it using the witness solved by ProveKit for
//! `"satoshi"` (while rejecting `"vitalik"`).

mod bqs;
mod ext;
mod params;
mod praxis;
mod qap;
mod search;

use {
    anyhow::{ensure, Context, Result},
    argh::FromArgs,
    ark_bn254::{Fr, G1Projective, G2Projective},
    ark_ec::PrimeGroup,
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    bqs::{r1cs_to_bqs, WitnessBitMap},
    nargo::foreign_calls::DefaultForeignCallBuilder,
    nargo_cli::cli::compile_cmd::compile_workspace_full,
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::{input_parser::InputValue, InputMap},
    noirc_artifacts::program::ProgramArtifact,
    noirc_driver::CompileOptions,
    params::PraxisParams,
    praxis::{decrypt, encrypt, setup, FixedBaseTable},
    provekit_backend_bn254::{
        solve_witness_vec,
        witness::{LayerScheduler, WitnessBuilder},
        TranscriptSponge,
    },
    provekit_common::HashConfig,
    provekit_r1cs_compiler::noir_to_r1cs,
    rand::rng,
    std::{
        fs::File,
        path::{Path, PathBuf},
        time::Instant,
    },
    whir::transcript::{DomainSeparator, ProverState},
};

/// Praxis 100-bit Witness Encryption demo with a real ProveKit Noir circuit.
#[derive(FromArgs)]
struct Cli {
    /// path to the Noir circuit directory (default:
    /// noir-examples/praxis-satoshi)
    #[argh(
        option,
        short = 'c',
        default = "PathBuf::from(\"noir-examples/praxis-satoshi\")"
    )]
    circuit: PathBuf,

    /// path to the Prover.toml input file (default: <circuit>/Prover.toml)
    #[argh(option, short = 'i')]
    input: Option<PathBuf>,

    /// secret message to encrypt (UTF-8, max 32 bytes; default: "Hello from
    /// Praxis 100-bit WE!")
    #[argh(
        option,
        short = 'm',
        default = "String::from(\"Hello from Praxis 100-bit WE!\")"
    )]
    message: String,

    /// optional 7-byte ASCII name override for decryption (e.g. "satoshi" or
    /// "vitalik")
    #[argh(option, short = 'n')]
    name: Option<String>,
}

/// Compile a Noir workspace using the embedded `nargo_cli` (matching ProveKit's
/// Noir version) and return the path to `target/<pkg>.json`.
fn compile_noir_circuit(circuit_dir: &Path) -> Result<PathBuf> {
    let toml_path = circuit_dir
        .join("Nargo.toml")
        .canonicalize()
        .with_context(|| format!("missing Nargo.toml in {}", circuit_dir.display()))?;
    let workspace = resolve_workspace_from_toml(&toml_path, PackageSelection::DefaultOrAll, None)?;
    compile_workspace_full(&workspace, &CompileOptions::default(), None)?;

    let pkg = workspace
        .members
        .first()
        .context("Noir workspace has no packages")?;
    let artifact = circuit_dir.join(format!("target/{}.json", pkg.name));
    ensure!(
        artifact.exists(),
        "compiled artifact not found at {}",
        artifact.display()
    );
    Ok(artifact)
}

/// Execute the compiled Noir program on `input_map` and solve the full ProveKit
/// R1CS witness.
fn solve_provekit_witness_from_inputs(
    program: &ProgramArtifact,
    witness_builders: &[WitnessBuilder],
    num_witnesses_for_solving: usize,
    input_map: &InputMap,
) -> Result<Vec<Fr>> {
    let initial_witness = program.abi.encode(input_map, None)?;

    let solver = Bn254BlackBoxSolver::default();
    let mut output_buf = Vec::new();
    let mut foreign_calls = DefaultForeignCallBuilder {
        output:       &mut output_buf,
        enable_mocks: false,
        resolver_url: None,
        root_path:    None,
        package_name: None,
    }
    .build();

    let mut stack = nargo::ops::execute_program(
        &program.bytecode,
        initial_witness,
        &solver,
        &mut foreign_calls,
    )
    .context("Noir program execution failed (constraints not satisfied)")?;

    let acir_map = stack.pop().context("missing ACIR witness stack")?.witness;

    let scheduler = LayerScheduler::new(witness_builders);
    let layers = scheduler.build_layers();

    let mut witness: Vec<Option<Fr>> = vec![None; num_witnesses_for_solving];
    let ds = DomainSeparator::protocol(&"praxis-demo").instance(&0u8);
    let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(HashConfig::Sha256));
    solve_witness_vec(&mut witness, layers, &acir_map, &mut merlin)?;

    witness
        .into_iter()
        .map(|v| v.context("unsolved R1CS witness entry"))
        .collect()
}

/// Build an `InputMap` for `name_bits: [bool; 56]` from a 7-byte ASCII string.
fn name_to_input_map(name: &str) -> Result<InputMap> {
    let bytes = name.as_bytes();
    ensure!(
        bytes.len() == 7,
        "name must be exactly 7 ASCII bytes, got {} ('{}')",
        bytes.len(),
        name
    );
    let mut bits = Vec::with_capacity(56);
    for &byte in bytes {
        for k in 0..8 {
            bits.push(InputValue::Field(u128::from((byte >> k) & 1).into()));
        }
    }
    let mut map = InputMap::new();
    map.insert("name_bits".to_string(), InputValue::Vec(bits));
    Ok(map)
}

/// Encode a 7-byte ASCII name directly into the 56-bit BQS witness `[1, b_0,
/// ..., b_55]` for demonstrating wrong-witness decryption rejection.
fn encode_name_bits_as_witness(name: &str, bit_map: &WitnessBitMap) -> Result<Vec<u8>> {
    let bytes = name.as_bytes();
    ensure!(
        bytes.len() == 7,
        "name must be exactly 7 ASCII bytes, got {} ('{}')",
        bytes.len(),
        name
    );
    ensure!(
        bit_map.n_unknowns >= 56,
        "BQS has {} unknowns (< 56)",
        bit_map.n_unknowns
    );
    let mut w = vec![0u8; bit_map.n_unknowns + 1];
    w[0] = 1;
    for (b_idx, &byte) in bytes.iter().enumerate() {
        for k in 0..8 {
            w[1 + b_idx * 8 + k] = (byte >> k) & 1;
        }
    }
    Ok(w)
}

fn main() -> Result<()> {
    let cli: Cli = argh::from_env();
    provekit_backend_bn254::register();

    let params = PraxisParams::table4_100bit();
    let msg_bytes = cli.message.as_bytes();
    ensure!(
        msg_bytes.len() <= params.msg_bytes,
        "message too long ({} bytes, max {})",
        msg_bytes.len(),
        params.msg_bytes
    );
    let mut msg_padded = vec![0u8; params.msg_bytes];
    msg_padded[..msg_bytes.len()].copy_from_slice(msg_bytes);

    println!("==================================================================");
    println!("  Praxis Witness Encryption + ProveKit Noir Demo");
    println!("  Security : {}", params.name);
    println!(
        "  Params   : lambda={}, n={}, d_R={}, k={}, K1={}, K2={}, g={}",
        params.lambda, params.n, params.d_r, params.k, params.k1, params.k2, params.g
    );
    println!("  Threads  : {}", rayon::current_num_threads());
    println!("==================================================================\n");

    // 1. Compile Noir circuit -> ACIR -> ProveKit R1CS.
    let t0 = Instant::now();
    let artifact_path = compile_noir_circuit(&cli.circuit)?;
    let program: ProgramArtifact = serde_json::from_reader(File::open(&artifact_path)?)?;
    ensure!(
        program.bytecode.functions.len() == 1,
        "expected single Noir entry point"
    );
    let main_fn = &program.bytecode.functions[0];
    let (r1cs, _witness_map, witness_builders) = noir_to_r1cs(main_fn)?;

    let has_challenges = witness_builders
        .iter()
        .any(|b| matches!(b, WitnessBuilder::Challenge(_)));
    ensure!(
        !has_challenges,
        "compiled R1CS contains Challenge builders; use Boolean constraints for direct BQS"
    );

    println!(
        "[1] Noir -> ProveKit R1CS ({:.2?}): {} witnesses, {} constraints, {} public inputs, 0 \
         challenges",
        t0.elapsed(),
        r1cs.num_witnesses(),
        r1cs.num_constraints(),
        r1cs.num_public_inputs
    );

    // 2. Convert ProveKit R1CS -> Praxis BQS & run deterministic Praxis Setup.
    let t1 = Instant::now();
    let (bqs, bit_map) = r1cs_to_bqs(&r1cs, &[])?;
    let raw_nc = bqs.constraints.len();
    let pp = setup(bqs, params.clone())?;
    let ell = params.ell(pp.qap.bqs.n_unknowns);
    println!("[2] R1CS -> BQS & Praxis Setup ({:.2?}):", t1.elapsed());
    println!(
        "    N = {} Boolean unknowns ({} native bools, {} expanded Fr), n_c = {} (padded from {} \
         to meet n <= D)",
        pp.qap.bqs.n_unknowns,
        bit_map.num_native_bools,
        bit_map.num_expanded_fields,
        pp.qap.bqs.constraints.len(),
        raw_nc
    );
    println!(
        "    QAP: nu = {}, D = {} evaluation points, |H| = {}, MSIS matrix: {}x{} over R_q (ell \
         <= k => trivial kernel)",
        pp.qap.nu, pp.qap.d, pp.qap.domain_h.size, params.k, ell
    );

    // 3. One-time fixed-base generator tables (reusable across all ciphertexts).
    let t_tbl = Instant::now();
    let g1_table = FixedBaseTable::new(G1Projective::generator());
    let g2_table = FixedBaseTable::new(G2Projective::generator());
    println!(
        "[3] One-time fixed-base tables (12-bit signed windows): {:.2?}",
        t_tbl.elapsed()
    );

    // 4. Encrypt secret message to the Noir circuit statement (needs NO witness!).
    let mut rng = rng();
    println!("\n[4] Encrypting secret message: \"{}\"", cli.message);
    let (ct, enc_t) = encrypt(&pp, &msg_padded, &g1_table, &g2_table, &mut rng)?;
    let (n_g1, n_g2, n_gt) = ct.element_counts();
    let ct_mb = ct.compressed_bytes() as f64 / (1024.0 * 1024.0);
    println!(
        "    Ciphertext: {:.2} MiB compressed ({} G1, {} G2, {} GT)",
        ct_mb, n_g1, n_g2, n_gt
    );
    println!(
        "    Enc time  : {:.2?} (field: {:.2?}, G1 muls: {:.2?}, G2 muls: {:.2?})",
        enc_t.total, enc_t.field_work, enc_t.g1_muls, enc_t.g2_muls
    );

    // 5. Decrypt using the witness solved by ProveKit (or CLI --name override).
    println!("\n[5] Solving witness with ProveKit & decrypting...");
    let w_bits = if let Some(ref name) = cli.name {
        println!("    Using CLI --name=\"{}\"", name);
        let input_map = name_to_input_map(name)?;
        match solve_provekit_witness_from_inputs(
            &program,
            &witness_builders,
            r1cs.num_witnesses_for_solving(),
            &input_map,
        ) {
            Ok(r1cs_witness) => bit_map.expand_witness(&r1cs_witness)?,
            Err(_) => {
                println!(
                    "    Noir execution rejected \"{}\" (expected for wrong name); feeding raw \
                     bits to Praxis::Dec...",
                    name
                );
                encode_name_bits_as_witness(name, &bit_map)?
            }
        }
    } else {
        let input_path = cli.input.unwrap_or_else(|| cli.circuit.join("Prover.toml"));
        println!("    Solving witness from {}", input_path.display());
        let (input_map, _ret) = read_inputs_from_file(&input_path, &program.abi)
            .with_context(|| format!("reading inputs from {}", input_path.display()))?;
        let r1cs_witness = solve_provekit_witness_from_inputs(
            &program,
            &witness_builders,
            r1cs.num_witnesses_for_solving(),
            &input_map,
        )?;
        bit_map.expand_witness(&r1cs_witness)?
    };

    let sat = pp.qap.bqs.is_satisfied(&w_bits)?;
    println!(
        "    BQS satisfied by witness: {} (wt(w) = {}/{})",
        sat,
        w_bits[1..].iter().filter(|&&b| b == 1).count(),
        pp.qap.bqs.n_unknowns
    );

    let (dec_opt, dec_t) = decrypt(&pp, &ct, &w_bits, &mut rng)?;
    println!(
        "    Dec time  : {:.2?} (forms+QAP: {:.2?}, MSMs+pairings: {:.2?}, BSGS search: {:.2?})",
        dec_t.total, dec_t.forms_and_qap, dec_t.group_comb_and_pairings, dec_t.search
    );
    println!(
        "    Search    : b_bar={}, baby_steps={}, giant_steps={}, false_fp_hits={}, t={:?}",
        dec_t.search_stats.b_bar,
        dec_t.search_stats.baby_steps,
        dec_t.search_stats.giant_steps,
        dec_t.search_stats.false_fp_hits,
        dec_t.recovered_t
    );

    match dec_opt {
        Some(pt) => {
            let trimmed = pt
                .iter()
                .copied()
                .take_while(|&b| b != 0)
                .collect::<Vec<_>>();
            let recovered = String::from_utf8_lossy(&trimmed);
            println!("    Decrypted : \"{}\"", recovered);
            ensure!(
                pt == msg_padded,
                "decrypted bytes do not match original message!"
            );
            println!("    Status    : SUCCESS (exact match!)");
        }
        None => {
            println!("    Decrypted : <bottom / decryption failed>");
            if sat {
                anyhow::bail!("unexpected decryption failure on a valid witness!");
            }
        }
    }

    // 6. Negative test: demonstrate that wrong name ("vitalik") cannot decrypt.
    if cli.name.is_none() {
        println!("\n[6] Negative check: attempting decryption with wrong name \"vitalik\"...");
        let wrong_w = encode_name_bits_as_witness("vitalik", &bit_map)?;
        let (wrong_dec, wrong_t) = decrypt(&pp, &ct, &wrong_w, &mut rng)?;
        ensure!(
            wrong_dec.is_none(),
            "SECURITY BUG: wrong name should never decrypt!"
        );
        println!(
            "    Result    : REJECTED (<bottom>) in {:.2?}",
            wrong_t.total
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            bqs::{Bqs, BqsConstraint},
            ext::FormMatrix,
            qap::poly_eval,
            search::{gt_pow_signed, PalindromicRecurrence},
        },
        ark_bn254::{Bn254, Fq, G1Affine, G2Affine},
        ark_ec::{pairing::Pairing, AffineRepr},
        ark_ff::{One, PrimeField},
        rand::{RngCore, SeedableRng},
    };

    #[test]
    fn test_palindromic_recurrence_matches_exact_gt_powers() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let gt_gen = Bn254::pairing(G1Affine::generator(), G2Affine::generator()).0;
        let g = gt_pow_signed(gt_gen, 123_456_789);
        let a = gt_pow_signed(gt_gen, 987_654_321);
        let rec = PalindromicRecurrence::from_generator(g);

        let rho: [Fq; 6] = std::array::from_fn(|_| {
            let mut b = [0u8; 64];
            rng.fill_bytes(&mut b);
            Fq::from_le_bytes_mod_order(&b)
        });
        let eval_lf = |v: &ark_bn254::Fq12| -> Fq {
            let c = &v.c0;
            rho[0] * c.c0.c0
                + rho[1] * c.c0.c1
                + rho[2] * c.c1.c0
                + rho[3] * c.c1.c1
                + rho[4] * c.c2.c0
                + rho[5] * c.c2.c1
        };

        let mut cur = a;
        let mut exact = Vec::new();
        for _ in 0..64 {
            exact.push(eval_lf(&cur));
            cur *= g;
        }

        let mut ring = [Fq::from(0u64); 12];
        ring.copy_from_slice(&exact[..12]);
        for &expected in &exact[12..] {
            let next = rec.step(&ring);
            assert_eq!(next, expected, "recurrence diverged from exact Gt power");
            ring.copy_within(1..12, 0);
            ring[11] = next;
        }
    }

    #[test]
    fn test_form_matrix_z_vector_matches_witness_eval() {
        let params = PraxisParams::tiny_test();
        let seed = [7u8; 32];
        let n_u = 5;
        let fm = FormMatrix::from_seed(&seed, &params, n_u);
        let w = vec![1u8, 1, 0, 1, 1, 0];
        let phi = fm.eval_forms_at_witness(&w);
        let x = Fr::from(12345u64);
        let z_vec = fm.eval_z_vector(x);

        let lhs: Fr = z_vec
            .iter()
            .zip(w.iter())
            .map(|(&zv, &wb)| if wb != 0 { zv } else { Fr::from(0u64) })
            .sum();
        let rhs = poly_eval(&phi, x);
        assert_eq!(lhs, rhs, "z[x] . w must equal sum_e phi_e(w) x^e");
    }

    #[test]
    fn test_praxis_example_2_1_roundtrip_and_rejection() -> Result<()> {
        // Example 2.1 (p. 9): w1 * w3 = 1, w2 * (w1 + w3) = 0, unique witness w = (1,
        // 1, 0, 1).
        let bqs = Bqs {
            n_unknowns:  3,
            f_max:       1,
            constraints: vec![
                BqsConstraint {
                    products: vec![(vec![(1, Fr::one())], vec![(3, Fr::one())])],
                    c:        vec![(0, Fr::one())],
                },
                BqsConstraint {
                    products: vec![(vec![(2, Fr::one())], vec![(1, Fr::one()), (3, Fr::one())])],
                    c:        vec![],
                },
            ],
        };

        let params = PraxisParams::tiny_test();
        let pp = setup(bqs, params)?;
        let g1_tbl = FixedBaseTable::new(G1Projective::generator());
        let g2_tbl = FixedBaseTable::new(G2Projective::generator());
        let mut rng = rand::rngs::StdRng::seed_from_u64(1337);

        let msg = b"praxis-toy-system-secret-32bytes";
        let (ct, _) = encrypt(&pp, msg, &g1_tbl, &g2_tbl, &mut rng)?;

        // Valid witness w = (1, 1, 0, 1).
        let (pt, _) = decrypt(&pp, &ct, &[1, 1, 0, 1], &mut rng)?;
        assert_eq!(pt.as_deref(), Some(msg.as_slice()));

        // Invalid witness w = (1, 1, 1, 1).
        let (bad, _) = decrypt(&pp, &ct, &[1, 1, 1, 1], &mut rng)?;
        assert!(bad.is_none());

        Ok(())
    }
}
