//! Synthesize ProveKit's actual passport Noir circuits via `noir_to_r1cs` +
//! `optimize_r1cs`, inspect their exact R1CS sizes, challenge counts, and
//! witness bit-width structure, and compute exact 100-bit Praxis costs
//! (Proposition 5.7 & Section 6.3).

use {
    anyhow::Result,
    ark_bn254::Fr,
    ark_ff::Zero,
    noirc_artifacts::program::ProgramArtifact,
    provekit_backend_bn254::witness::WitnessBuilder,
    provekit_common::R1CS,
    provekit_r1cs_compiler::{noir_to_r1cs, optimize_r1cs},
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

fn praxis_100bit_stats(n_bools: usize, n_c_raw: usize) -> (f64, f64, f64, f64) {
    // Table 4 100-bit parameters: n=4608, K1=192, K2=12, g=1.736375e15, nu=2 (R1CS)
    let n_ext = 4608usize;
    let k1 = 192usize;
    let k2 = 12usize;
    let nu = 2usize;
    let g = 1_736_375_024_658_487.0f64;

    let n_c = n_c_raw
        .max(n_ext.saturating_sub(n_bools + 2).div_ceil(nu))
        .max(1);
    let d = n_bools + 2 + nu * n_c;
    // Optimal chunking J ~ sqrt(D / n_ext), J' ~ sqrt(nu*n_c / n_ext)
    let j_quo = ((d as f64 / (1.5 * n_ext as f64)).sqrt().round() as usize).max(1);
    let j_rem = (((nu * n_c) as f64 / (1.5 * n_ext as f64)).sqrt().round() as usize).max(1);
    let delta_quo = d.div_ceil(j_quo);
    let delta_rem = (nu * n_c).div_ceil(j_rem);

    // Proposition 5.7(a) element counts
    let n1 = (2 * k1 + 1) * (n_bools + 1) + delta_quo + (delta_rem / nu);
    let n2 = 6 * k2 * (n_bools + 1) + 3 * k2 + (3 * n_ext / 2) * (j_quo + j_rem) + 13 * n_ext - 8;
    let g2_total = 2 * n2;

    // Standard compressed (32 B / G1, 64 B / G2 -> ~20.06 KiB per Boolean unknown
    // at Table 4 params). Matches paper's ~7.88 GiB for N = 391,693.
    let ct_gib = (n1 as f64 * 32.0 + g2_total as f64 * 64.0) / (1024.0_f64.powi(3));

    // Measured 16-core Apple Silicon throughput from our praxis-demo run:
    // Enc: 3.29M G1/s, 1.17M G2/s
    let enc_sec = (n1 as f64 / 3.29e6) + (g2_total as f64 / 1.17e6);

    // Expected BSGS search steps: E[|t|] ~ 0.7979 * g * sqrt((N + 4) / 48)
    // Optimal baby + expected giant steps ~ 2 * sqrt(E[|t|])
    let exp_abs_t = 0.797_884_56 * g * (((n_bools + 4) as f64) / 48.0).sqrt();
    let exp_steps = 2.0 * exp_abs_t.sqrt();
    // Measured 16-core Apple Silicon recurrence rate: 56.5M steps/s
    let dec_search_sec = exp_steps / 56.5e6;
    // Baby-step table RAM: sqrt(E[|t|]) * 12 bytes
    let table_gib = (exp_abs_t.sqrt() * 12.0) / (1024.0_f64.powi(3));

    (ct_gib, enc_sec, dec_search_sec, table_gib)
}

fn inspect(label: &str, json_path: &str) -> Result<()> {
    let path = Path::new(json_path);
    let program: ProgramArtifact = serde_json::from_reader(File::open(path)?)?;
    let main = &program.bytecode.functions[0];
    let (mut r1cs, mut wmap, mut builders) = noir_to_r1cs(main)?;
    let pub_set: HashSet<u32> = main.public_inputs().indices().iter().copied().collect();
    r1cs.num_public_inputs = pub_set.len();

    let raw_w = r1cs.num_witnesses();
    let raw_c = r1cs.num_constraints();
    let raw_challenges = builders
        .iter()
        .filter(|b| matches!(b, WitnessBuilder::Challenge(_)))
        .count();

    let _opt = optimize_r1cs(&mut r1cs, &mut builders, &mut wmap, &pub_set)?;
    let opt_w = r1cs.num_witnesses();
    let opt_c = r1cs.num_constraints();
    let opt_challenges = builders
        .iter()
        .filter(|b| matches!(b, WitnessBuilder::Challenge(_)))
        .count();

    // Count witness builder types & digit decomposition bit-widths.
    let mut wb_counts: HashMap<&'static str, usize> = HashMap::new();
    let mut digit_widths: HashMap<usize, usize> = HashMap::new();
    for b in &builders {
        let name = match b {
            WitnessBuilder::Constant(..) => "Constant",
            WitnessBuilder::Acir(..) => "Acir",
            WitnessBuilder::Sum(..) => "Sum",
            WitnessBuilder::Product(..) => "Product",
            WitnessBuilder::Inverse(..) => "Inverse",
            WitnessBuilder::Challenge(..) => "Challenge",
            WitnessBuilder::DigitalDecomposition(dd) => {
                // output_indices has len = log_bases.len() * num_witnesses_to_decompose
                let nw = dd.num_witnesses_to_decompose;
                for (i, &w_idx) in dd.output_indices.iter().enumerate() {
                    let lb = dd.log_bases[i / nw.max(1)];
                    digit_widths.insert(w_idx, lb);
                }
                "DigitalDecomp"
            }
            WitnessBuilder::LogUpInverse(..) => "LogUpInverse",
            WitnessBuilder::MultiplicitiesForRange(..) => "RangeMult",
            WitnessBuilder::BinOpLookupDenominator(..) => "BinOpDenom",
            WitnessBuilder::SpreadBitExtract { .. } => "SpreadExtract",
            WitnessBuilder::SpiceWitnesses(..) => "SpiceRAM",
            _ => "Other",
        };
        *wb_counts.entry(name).or_default() += 1;
    }

    let bool_cols = detect_bool_cols(&r1cs);
    let priv_w = opt_w.saturating_sub(1 + r1cs.num_public_inputs);
    let n_bools_detected = bool_cols.len();
    let n_non_bool = priv_w.saturating_sub(n_bools_detected);

    // 1. Naive generic expansion (254 bits per non-bool Fr witness)
    let n_naive = n_bools_detected + n_non_bool * 254;
    // 2. Digit-aware expansion (if LogUp/Challenge tables are removed and known
    //    digits use their bit-width)
    let mut n_tight = 0usize;
    let mut digit_count = 0usize;
    for col in (1 + r1cs.num_public_inputs)..opt_w {
        if bool_cols.contains(&col) {
            n_tight += 1;
        } else if let Some(&bits) = digit_widths.get(&col) {
            n_tight += bits;
            digit_count += 1;
        } else {
            n_tight += 254;
        }
    }

    println!("=========================================================================");
    println!("Circuit: {label}");
    println!("  ACIR opcodes      : {}", main.opcodes.len());
    println!(
        "  Raw R1CS          : {raw_w:>8} witnesses, {raw_c:>8} constraints, {raw_challenges} \
         challenges"
    );
    println!(
        "  Optimized R1CS    : {opt_w:>8} witnesses, {opt_c:>8} constraints, {} pub inputs, \
         {opt_challenges} challenges",
        r1cs.num_public_inputs
    );
    println!(
        "  R1CS nonzeros     : A={}, B={}, C={} (total={})",
        r1cs.a.num_entries(),
        r1cs.b.num_entries(),
        r1cs.c.num_entries(),
        r1cs.a.num_entries() + r1cs.b.num_entries() + r1cs.c.num_entries()
    );
    let mut wb_sorted: Vec<_> = wb_counts.into_iter().collect();
    wb_sorted.sort_by(|a, b| b.1.cmp(&a.1));
    println!(
        "  Top builders      : {:?}",
        &wb_sorted[..wb_sorted.len().min(7)]
    );
    println!(
        "  Witness breakdown : {n_bools_detected} bools, {digit_count} decomposed digits, {} \
         general Fr",
        priv_w.saturating_sub(n_bools_detected + digit_count)
    );

    let (ct_n, enc_n, dec_n, ram_n) = praxis_100bit_stats(n_naive, opt_c);
    println!(
        "  [Direct BQS naive 254b/Fr] N = {:>10} -> CT = {:>7.2} GiB, Enc ~ {:>6.0}s, Search ~ \
         {:>5.1}s ({:.2} GiB RAM)",
        n_naive, ct_n, enc_n, dec_n, ram_n
    );
    let (ct_t, enc_t, dec_t, ram_t) = praxis_100bit_stats(n_tight, opt_c);
    println!(
        "  [Direct BQS digit-tight  ] N = {:>10} -> CT = {:>7.2} GiB, Enc ~ {:>6.0}s, Search ~ \
         {:>5.1}s ({:.2} GiB RAM)",
        n_tight, ct_t, enc_t, dec_t, ram_t
    );
    Ok(())
}

fn main() -> Result<()> {
    provekit_backend_bn254::register();

    let circuits = [
        (
            "praxis-satoshi (our demo)",
            "noir-examples/praxis-satoshi/target/praxis_satoshi.json",
        ),
        (
            "merkle_age_check / t_attest (Poseidon2 Merkle + age check)",
            "noir-examples/noir-passport/merkle_age_check/target/t_attest.json",
        ),
        (
            "merkle_age_check / t_add_integrity_commit",
            "noir-examples/noir-passport/merkle_age_check/target/t_add_integrity_commit.json",
        ),
        (
            "merkle_age_check / t_add_id_data_720 (SHA256 + RSA)",
            "noir-examples/noir-passport/merkle_age_check/target/t_add_id_data_720.json",
        ),
        (
            "merkle_age_check / t_add_dsc_720 (RSA CSCA->DSC)",
            "noir-examples/noir-passport/merkle_age_check/target/t_add_dsc_720.json",
        ),
        (
            "complete_age_check (monolithic full passport + age check)",
            "noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.\
             json",
        ),
    ];

    for (label, path) in circuits {
        inspect(label, path)?;
    }

    let (ct_g, enc_g, dec_g, ram_g) = praxis_100bit_stats(391_693, 1_694);
    println!("=========================================================================");
    println!("Reference: Praxis Paper Groth16 Verifier (Section 6.1, universal for ANY circuit)");
    println!(
        "  [Groth16 BQS (paper)     ] N = {:>10} -> CT = {:>7.2} GiB, Enc ~ {:>6.1}s, Search ~ \
         {:>5.1}s ({:.2} GiB RAM)",
        391_693, ct_g, enc_g, dec_g, ram_g
    );
    Ok(())
}
