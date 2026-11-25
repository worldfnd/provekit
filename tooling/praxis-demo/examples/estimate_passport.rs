//! Benchmark & cost comparison of **Direct BQS** vs. **Pure-Rust Spartan +
//! HyperKZG (2 pairings)** vs. **Groth16 (paper)** across ProveKit's actual
//! passport Noir circuits (`praxis-satoshi`, `t_attest`, `t_add_*`,
//! `complete_age_check`).
//!
//! Runs **real end-to-end 2-round Spartan + HyperKZG proving & 2-pairing
//! verification** over BN254 with a single shared universal Powers-of-Tau SRS!

use {
    anyhow::{Context, Result},
    ark_bn254::{Fr, G1Projective},
    ark_ec::PrimeGroup,
    ark_ff::Zero,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_artifacts::program::ProgramArtifact,
    praxis_demo::{
        kzg::{
            bqs_cost::{estimate_full_kzg_verifier_bqs, praxis_100bit_costs},
            spartan::{prove, verify, SpartanKzgCircuit},
            univariate::KzgSrs,
        },
        praxis::FixedBaseTable,
    },
    provekit_backend_bn254::witness::WitnessBuilder,
    provekit_common::R1CS,
    provekit_r1cs_compiler::{noir_to_r1cs, optimize_r1cs},
    rand::{rngs::StdRng, SeedableRng},
    std::{
        collections::{HashMap, HashSet},
        fs::File,
        path::Path,
    },
};

fn detect_bool_cols(r1cs: &R1CS<Fr>) -> HashSet<usize> {
    let (a, b, c) = (r1cs.a(), r1cs.b(), r1cs.c());
    let mut bool_cols = HashSet::new();
    for row in 0..r1cs.num_constraints() {
        let ra: Vec<_> = a.iter_row(row).collect();
        let rb: Vec<_> = b.iter_row(row).collect();
        let rc: Vec<_> = c.iter_row(row).collect();
        if ra.len() == 1 && rb.len() == 1 && rc.len() == 1 {
            let ((ja, ca), (jb, cb), (jc, cc)) = (ra[0], rb[0], rc[0]);
            if ja > 0 && ja == jb && jb == jc && ca * cb == cc && !cc.is_zero() {
                bool_cols.insert(ja);
                continue;
            }
        }
        if rc.is_empty() {
            let check = |s: &[(usize, Fr)], p: &[(usize, Fr)]| -> Option<usize> {
                if s.len() == 1 && p.len() == 2 && s[0].0 > 0 && !s[0].1.is_zero() {
                    let j = s[0].0;
                    let (mut c0, mut cj) = (Fr::zero(), Fr::zero());
                    for &(col, val) in p {
                        if col == 0 {
                            c0 = val;
                        } else if col == j {
                            cj = val;
                        } else {
                            return None;
                        }
                    }
                    if !cj.is_zero() && c0 == -cj {
                        return Some(j);
                    }
                }
                None
            };
            if let Some(j) = check(&ra, &rb).or_else(|| check(&rb, &ra)) {
                bool_cols.insert(j);
            }
        }
    }
    bool_cols
}

fn direct_bqs_stats(program: &ProgramArtifact) -> Result<(usize, f64, usize, usize)> {
    let main = &program.bytecode.functions[0];
    let (mut r1cs, mut wmap, mut builders) = noir_to_r1cs(main)?;
    let pub_set: HashSet<u32> = main.public_inputs().indices().iter().copied().collect();
    r1cs.num_public_inputs = pub_set.len();
    let _opt = optimize_r1cs(&mut r1cs, &mut builders, &mut wmap, &pub_set)?;

    let mut digit_widths: HashMap<usize, usize> = HashMap::new();
    for b in &builders {
        if let WitnessBuilder::DigitalDecomposition(dd) = b {
            let nw = dd.num_witnesses_to_decompose;
            for (i, &w_idx) in dd.output_indices.iter().enumerate() {
                let lb = dd.log_bases[i / nw.max(1)];
                digit_widths.insert(w_idx, lb);
            }
        }
    }
    let bool_cols = detect_bool_cols(&r1cs);
    let mut n_tight = 0usize;
    for col in (1 + r1cs.num_public_inputs)..r1cs.num_witnesses() {
        if bool_cols.contains(&col) {
            n_tight += 1;
        } else if let Some(&bits) = digit_widths.get(&col) {
            n_tight += bits;
        } else {
            n_tight += 254;
        }
    }
    let (ct_gib, _, _, _) = praxis_100bit_costs(n_tight, r1cs.num_constraints(), 2);
    Ok((n_tight, ct_gib, r1cs.num_witnesses(), r1cs.num_constraints()))
}

fn main() -> Result<()> {
    provekit_backend_bn254::register();

    let circuits: Vec<(&str, &str, &str)> = vec![
        (
            "praxis-satoshi",
            "noir-examples/praxis-satoshi/target/praxis_satoshi.json",
            "noir-examples/praxis-satoshi/Prover.toml",
        ),
        (
            "t_attest (Merkle + age)",
            "noir-examples/noir-passport/merkle_age_check/target/t_attest.json",
            "noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/t_attest.toml",
        ),
        (
            "t_add_integrity_commit",
            "noir-examples/noir-passport/merkle_age_check/target/t_add_integrity_commit.json",
            "noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/\
             t_add_integrity_commit.toml",
        ),
        (
            "t_add_id_data_720",
            "noir-examples/noir-passport/merkle_age_check/target/t_add_id_data_720.json",
            "noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/\
             t_add_id_data_720.toml",
        ),
        (
            "t_add_dsc_720",
            "noir-examples/noir-passport/merkle_age_check/target/t_add_dsc_720.json",
            "noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/\
             t_add_dsc_720.toml",
        ),
        (
            "complete_age_check",
            "noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.\
             json",
            "noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml",
        ),
    ];

    println!("Preparing universal BN254 KZG SRS (2^20 = 1,048,576 G1 points)...");
    let mut rng = StdRng::seed_from_u64(2026);
    let g1_tbl = FixedBaseTable::new(G1Projective::generator());
    let (srs, srs_time) = KzgSrs::setup_with_table(1usize << 20, &g1_tbl, &mut rng)?;
    println!(
        "Universal SRS ready in {:.2?} (one-time, shared across ALL circuits!)\n",
        srs_time
    );

    println!(
        "{:<24} | {:>10} | {:>9} | {:>9} | {:>8} | {:>8} | {:>9} | {:>8}",
        "Circuit",
        "Direct CT",
        "KZG Prove",
        "KZG Verif",
        "Proof KB",
        "Pairings",
        "KZG BQS N",
        "KZG->WE"
    );
    println!("{}", "-".repeat(106));

    for (label, json_path, toml_path) in circuits {
        let program: ProgramArtifact =
            serde_json::from_reader(File::open(Path::new(json_path))?)?;
        let (_n_direct, direct_ct_gib, _opt_w, _opt_c) = direct_bqs_stats(&program)?;

        let circuit = SpartanKzgCircuit::prepare(program)?;
        let (input_map, _ret) = read_inputs_from_file(Path::new(toml_path), &circuit.program.abi)
            .with_context(|| format!("reading inputs from {toml_path}"))?;

        let (proof, prove_t) = prove(&circuit, &srs, &input_map)?;
        let (_vdata, verify_t) = verify(&circuit, &srs, &proof)?;

        let est = estimate_full_kzg_verifier_bqs(
            circuit.m_0,
            circuit.m_w1,
            circuit.m_w2,
            circuit.is_dual_mode(),
        );

        let direct_str = if direct_ct_gib >= 1024.0 {
            format!("{:.2} TiB", direct_ct_gib / 1024.0)
        } else if direct_ct_gib < 1.0 {
            format!("{:.1} MiB", direct_ct_gib * 1024.0)
        } else {
            format!("{:.1} GiB", direct_ct_gib)
        };

        println!(
            "{:<24} | {:>10} | {:>8.2?} | {:>8.2?} | {:>6.2}KB | {:>8} | {:>9} | {:>6.2}GiB",
            label,
            direct_str,
            prove_t.total,
            verify_t.total,
            proof.compressed_bytes() as f64 / 1024.0,
            verify_t.num_pairings,
            est.n_total,
            est.ct_gib
        );
    }

    println!("{}", "-".repeat(106));
    let (ct_g, _, _, _) = praxis_100bit_costs(391_693, 1_694, 2048);
    println!(
        "{:<24} | {:>10} | {:>9} | {:>9} | {:>8} | {:>8} | {:>9} | {:>6.2}GiB",
        "Ref: Groth16 (paper)", "-", "-", "-", "0.19KB", 3, 391_693, ct_g
    );

    Ok(())
}
