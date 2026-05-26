//! `export-evm-proof` — turn a `proof.np` (Groth16 variant) into the calldata
//! the on-chain `ProvekitGroth16Verifier.verifyProof(bytes,uint256[N_PUB])`
//! expects.
//!
//! Output:
//!   * `<out_dir>/proof.hex`   — single line, `0x` + hex of the 384-byte EVM-BE
//!     proof (Ar(64) || Bs(128) || Krs(64) || Commit(64) || PoK(64)).
//!   * `<out_dir>/inputs.txt`  — one decimal field element per line, exactly
//!     N_PUB lines.
//!
//! Pair with:
//!   cast call <verifier_addr> \
//!     "verifyProof(bytes,uint256[N])" \
//!     $(cat proof.hex) \
//!     "[$(paste -sd, inputs.txt)]"
//!
//! The prover stores the Groth16 proof in arkworks **compressed** form (the
//! 192-byte representation in the postcard blob). On-chain we need
//! **uncompressed** points in EVM big-endian — gnark's `MarshalSolidity`
//! convention. This command performs that conversion.

use {
    super::Command,
    anyhow::{bail, Context, Result},
    argh::FromArgs,
    ark_bn254::{Fq, Fr, G1Affine, G2Affine},
    ark_ec::AffineRepr,
    ark_ff::{BigInteger, PrimeField},
    ark_serialize::CanonicalDeserialize,
    provekit_common::{file::read, NoirProof},
    provekit_groth16::Proof as Groth16Proof,
    std::{fmt::Write as _, fs, path::PathBuf},
    tracing::{info, instrument},
};

/// Re-emit a Groth16 NoirProof as EVM calldata for the on-chain verifier.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "export-evm-proof")]
pub struct Args {
    /// path to the prover output (`proof.np`)
    #[argh(option, long = "proof", short = 'p')]
    proof_path: PathBuf,

    /// directory for `proof.hex` + `inputs.txt` (created if missing)
    #[argh(option, long = "out-dir", short = 'o')]
    out_dir: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let proof: NoirProof = read(&self.proof_path)
            .with_context(|| format!("reading {}", self.proof_path.display()))?;

        let (public_inputs, proof_bytes) = match proof {
            NoirProof::Groth16 {
                public_inputs,
                groth16_proof,
            } => (public_inputs, groth16_proof),
            NoirProof::Whir { .. } => bail!(
                "proof at {} is a WHIR proof, not a Groth16 proof — re-prove with `--backend \
                 groth16`",
                self.proof_path.display(),
            ),
        };

        let g16: Groth16Proof = Groth16Proof::deserialize_compressed(proof_bytes.as_slice())
            .context("deserializing compressed Groth16 proof")?;
        if g16.commitments.len() != 1 {
            bail!(
                "this exporter only supports single-commitment proofs (got {} commitments)",
                g16.commitments.len()
            );
        }

        let mut evm = Vec::with_capacity(256 + 64 * (g16.commitments.len() + 1));
        push_g1_be(&mut evm, &g16.ar, "Ar")?;
        push_g2_be(&mut evm, &g16.bs, "Bs")?;
        push_g1_be(&mut evm, &g16.krs, "Krs")?;
        for (i, c) in g16.commitments.iter().enumerate() {
            push_g1_be(&mut evm, c, &format!("commitments[{i}]"))?;
        }
        push_g1_be(&mut evm, &g16.commitment_pok, "commitment_pok")?;

        let inputs: &[Fr] = &public_inputs.0;
        info!(
            evm_bytes = evm.len(),
            n_inputs = inputs.len(),
            "ready to write EVM calldata",
        );

        fs::create_dir_all(&self.out_dir)
            .with_context(|| format!("creating {}", self.out_dir.display()))?;

        let mut proof_hex = String::with_capacity(2 + evm.len() * 2);
        proof_hex.push_str("0x");
        for b in &evm {
            write!(&mut proof_hex, "{:02x}", b).unwrap();
        }
        let proof_hex_path = self.out_dir.join("proof.hex");
        fs::write(&proof_hex_path, &proof_hex)
            .with_context(|| format!("writing {}", proof_hex_path.display()))?;

        let mut inputs_txt = String::new();
        for (i, fr) in inputs.iter().enumerate() {
            // Emit as decimal — `cast` / `forge` parse uint256 args in decimal
            // (and hex too, but decimal needs no `0x` and trims fewer characters).
            // Use the raw bigint representation (canonical, not Montgomery).
            let big = fr.into_bigint();
            writeln!(&mut inputs_txt, "{big}")
                .with_context(|| format!("formatting public input {i}"))?;
        }
        let inputs_path = self.out_dir.join("inputs.txt");
        fs::write(&inputs_path, inputs_txt)
            .with_context(|| format!("writing {}", inputs_path.display()))?;

        info!(
            proof = %proof_hex_path.display(),
            inputs = %inputs_path.display(),
            "wrote EVM calldata",
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EVM-BE serialization helpers
// ---------------------------------------------------------------------------

/// Append a base-field element as 32 big-endian bytes.
fn push_fq_be(out: &mut Vec<u8>, f: &Fq) {
    let bytes = f.into_bigint().to_bytes_be();
    if bytes.len() < 32 {
        out.extend(std::iter::repeat(0).take(32 - bytes.len()));
    }
    out.extend_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
}

/// Append a G1 point as 64 bytes: X (BE) || Y (BE).
/// Errors on the point at infinity — the on-chain verifier rejects it.
fn push_g1_be(out: &mut Vec<u8>, p: &G1Affine, name: &str) -> Result<()> {
    let (x, y) = p
        .xy()
        .with_context(|| format!("{name} is the point at infinity"))?;
    push_fq_be(out, &x);
    push_fq_be(out, &y);
    Ok(())
}

/// Append a G2 point in EIP-197 ordering: X.c1, X.c0, Y.c1, Y.c0 — each 32
/// bytes BE. Mirrors gnark's `MarshalSolidity` for Bs / commitments-in-G2.
fn push_g2_be(out: &mut Vec<u8>, p: &G2Affine, name: &str) -> Result<()> {
    let (x, y) = p
        .xy()
        .with_context(|| format!("{name} is the point at infinity"))?;
    push_fq_be(out, &x.c1);
    push_fq_be(out, &x.c0);
    push_fq_be(out, &y.c1);
    push_fq_be(out, &y.c0);
    Ok(())
}
