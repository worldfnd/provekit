//! Praxis 100-bit Witness Encryption + ProveKit Noir Demo.
//!
//! Supports two modes via `--mode`:
//! - `direct`: Noir -> ProveKit `R1CS<Fr>` -> Praxis `Bqs` -> 100-bit Praxis WE
//!   (best for small challenge-free circuits like `noir-examples/praxis-satoshi`)
//! - `kzg`: Noir -> ProveKit 2-round `Spartan + HyperKZG` (pure-Rust BN254,
//!   universal SRS, **2 pairings**, zero Groth16 / zero gnark) -> Praxis WE
//!   (supports multi-challenge passport circuits like `t_attest` and
//!   `complete_age_check` at ~8 GiB verifier BQS)

use {
    anyhow::Result,
    argh::FromArgs,
    praxis_demo::{direct, kzg},
    std::path::PathBuf,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Direct,
    Kzg,
}

impl argh::FromArgValue for Mode {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "direct" => Ok(Self::Direct),
            "kzg" => Ok(Self::Kzg),
            other => Err(format!(
                "unknown mode '{other}'; expected 'direct' or 'kzg'"
            )),
        }
    }
}

/// Praxis 100-bit Witness Encryption demo with ProveKit (`direct` or `kzg`).
#[derive(FromArgs)]
struct Cli {
    /// proving/encryption mode: "direct" (default) or "kzg" (Spartan+HyperKZG)
    #[argh(option, short = 'M', default = "Mode::Direct")]
    mode: Mode,

    /// path to the Noir circuit directory or compiled .json artifact
    /// (default: noir-examples/praxis-satoshi)
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

    /// optional 7-byte ASCII name override for praxis-satoshi (e.g. "satoshi"
    /// or "vitalik")
    #[argh(option, short = 'n')]
    name: Option<String>,
}

fn main() -> Result<()> {
    let cli: Cli = argh::from_env();
    provekit_backend_bn254::register();

    match cli.mode {
        Mode::Direct => direct::run(
            &cli.circuit,
            cli.input.as_deref(),
            &cli.message,
            cli.name.as_deref(),
        ),
        Mode::Kzg => kzg::run(
            &cli.circuit,
            cli.input.as_deref(),
            &cli.message,
            cli.name.as_deref(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use {
        anyhow::Result,
        ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
        ark_ec::{pairing::Pairing, AffineRepr, PrimeGroup},
        ark_ff::{One, PrimeField},
        praxis_demo::{
            bqs::{Bqs, BqsConstraint},
            ext::FormMatrix,
            kzg::{
                spartan::{prove, verify, SpartanKzgCircuit},
                univariate::KzgSrs,
            },
            load_or_compile_noir,
            params::PraxisParams,
            praxis::{decrypt, encrypt, setup, FixedBaseTable},
            qap::poly_eval,
            search::{gt_pow_signed, PalindromicRecurrence},
        },
        rand::{RngCore, SeedableRng},
        std::path::Path,
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

        let (pt, _) = decrypt(&pp, &ct, &[1, 1, 0, 1], &mut rng)?;
        assert_eq!(pt.as_deref(), Some(msg.as_slice()));

        let (bad, _) = decrypt(&pp, &ct, &[1, 1, 1, 1], &mut rng)?;
        assert!(bad.is_none());

        Ok(())
    }

    #[test]
    fn test_spartan_hyperkzg_praxis_satoshi_roundtrip() -> Result<()> {
        provekit_backend_bn254::register();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let circuit_dir = root.join("noir-examples/praxis-satoshi");
        let program = load_or_compile_noir(&circuit_dir)?;
        let circuit = SpartanKzgCircuit::prepare(program)?;

        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let g1_tbl = FixedBaseTable::new(G1Projective::generator());
        let (srs, _) = KzgSrs::setup_with_table(circuit.required_srs_len(), &g1_tbl, &mut rng)?;

        let input_map = praxis_demo::direct::name_to_input_map("satoshi")?;
        let (proof, _) = prove(&circuit, &srs, &input_map)?;
        let (_vdata, vt) = verify(&circuit, &srs, &proof)?;
        assert_eq!(vt.num_pairings, 2);

        // Tamper with outer sumcheck -> must fail!
        let mut bad = proof.clone();
        bad.outer_sumcheck[0][0] += Fr::one();
        assert!(verify(&circuit, &srs, &bad).is_err());
        Ok(())
    }
}
