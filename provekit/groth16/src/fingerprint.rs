//! Deterministic 32-byte fingerprint binding a Groth16 trusted-setup
//! ceremony to the exact `(R1CS, CommitmentInfo)` it was run against.
//!
//! Why this exists: [`crate::setup::setup_from_ceremony`] previously
//! only validated *shape* — wire counts, basis lengths, commitment counts.
//! Two R1CSes with identical counts but different matrices, or with the
//! same matrices but a different public/private wire partition, both
//! passed shape validation while encoding completely different
//! polynomials in `pk.g1_k` / `vk.g1_k`. That produces proofs that either
//! reject on the pairing check or — worse — bind to the wrong public
//! inputs.
//!
//! Workflow:
//! 1. `export-gnark-r1cs` writes the gnark-r1cs JSON *and* a sidecar
//!    `<json>.fingerprint` containing this digest.
//! 2. The trusted-setup operator runs the ceremony against the JSON and
//!    delivers the resulting `pk`/`vk` *plus* the fingerprint sidecar.
//! 3. `prepare --groth16-fingerprint-in <sidecar>` re-derives the fingerprint
//!    from the current in-memory R1CS+commitments and `ensure!`s it matches;
//!    mismatch fails loud at the import boundary.
//!
//! Wire format (version 1, domain-separated). All integer fields are u64
//! little-endian; field elements are 32 big-endian bytes (canonical
//! representation, leading-zero padded to a fixed width).
//!
//! ```text
//!   DOMAIN_SEP_V1
//!   num_public_inputs : u64
//!   num_witnesses     : u64
//!   num_constraints   : u64
//!   for j in 0..num_constraints:
//!     for matrix in [A, B, C]:
//!       row_len : u64
//!       (col : u64, value : 32B big-endian) * row_len
//!         // entries in `SparseMatrix::iter_row` order
//!   num_commitments : u64
//!   for ci in commitment_info:
//!     |private_committed|                : u64,  (idx : u64)*
//!     |public_and_commitment_committed|  : u64,  (idx : u64)*
//!     |challenge_indices|                : u64,  (idx : u64)*
//!     nb_public_committed                : u64
//! ```
//!
//! Any future change to the encoding MUST bump the domain separator
//! suffix — old sidecars will then fail loud rather than silently match.

use {
    crate::CommitmentInfo,
    anyhow::{Context, Result},
    ark_ff::{BigInteger, PrimeField},
    provekit_common::R1CS,
    sha3::{Digest, Sha3_256},
};

/// Domain separator for fingerprint v1. Bump the trailing version on any
/// breaking change to the encoding below.
pub const DOMAIN_SEP_V1: &[u8] = b"provekit-gnark-r1cs-fingerprint-v1";

/// Compute the canonical 32-byte fingerprint of `(r1cs, commitment_info)`.
///
/// Two structurally identical inputs produce the same digest; any
/// difference in the A/B/C matrices, in the public-input count, in the
/// per-commitment private/public/challenge wire partition, or in the
/// commitment ordering produces a different digest. See module docs for
/// the wire format.
pub fn fingerprint(r1cs: &R1CS, commitment_info: &[CommitmentInfo]) -> Result<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_SEP_V1);
    h.update((r1cs.num_public_inputs as u64).to_le_bytes());
    h.update((r1cs.num_witnesses() as u64).to_le_bytes());
    let n_constraints = r1cs.num_constraints();
    h.update((n_constraints as u64).to_le_bytes());

    for j in 0..n_constraints {
        for matrix in [&r1cs.a, &r1cs.b, &r1cs.c] {
            // Buffer the row so we can prefix its length; `iter_row` does
            // not expose a cheap `len()` for delta-decoded rows.
            let row: Vec<_> = matrix.iter_row(j).collect();
            h.update((row.len() as u64).to_le_bytes());
            for (col, interned) in row {
                h.update((col as u64).to_le_bytes());
                let fe = r1cs
                    .interner
                    .get(interned)
                    .with_context(|| format!("fingerprint: interner missing value at row {j}"))?;
                h.update(fe_be32(&fe));
            }
        }
    }

    h.update((commitment_info.len() as u64).to_le_bytes());
    for ci in commitment_info {
        h.update((ci.private_committed.len() as u64).to_le_bytes());
        for &idx in &ci.private_committed {
            h.update((idx as u64).to_le_bytes());
        }
        h.update((ci.public_and_commitment_committed.len() as u64).to_le_bytes());
        for &idx in &ci.public_and_commitment_committed {
            h.update((idx as u64).to_le_bytes());
        }
        h.update((ci.challenge_indices.len() as u64).to_le_bytes());
        for &idx in &ci.challenge_indices {
            h.update((idx as u64).to_le_bytes());
        }
        h.update((ci.nb_public_committed as u64).to_le_bytes());
    }

    Ok(h.finalize().into())
}

/// BN254 scalar → 32-byte canonical big-endian.
///
/// `BigInt<4>::to_bytes_be` is fixed-width (32 bytes), so the conversion
/// is a direct array cast — no padding or truncation needed.
fn fe_be32(fe: &provekit_common::FieldElement) -> [u8; 32] {
    fe.into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("BN254 scalar canonicalizes to exactly 32 bytes")
}

/// Parse a hex-encoded fingerprint sidecar. Accepts optional `0x` prefix
/// and leading/trailing whitespace (the exporter writes `0x<64-hex>\n`).
pub fn parse_hex(s: &str) -> Result<[u8; 32]> {
    let trimmed = s.trim();
    let body = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    anyhow::ensure!(
        body.len() == 64,
        "fingerprint must be 64 hex chars (got {} chars after trim)",
        body.len()
    );
    let mut out = [0u8; 32];
    for (i, chunk) in body.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).context("fingerprint contains non-utf8 bytes")?;
        out[i] = u8::from_str_radix(s, 16)
            .with_context(|| format!("invalid hex digit at position {}", i * 2))?;
    }
    Ok(out)
}

/// Format a fingerprint as `0x`-prefixed lowercase hex. Sidecar files
/// produced by the exporter use this format.
pub fn to_hex(fp: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(2 + 64);
    s.push_str("0x");
    for b in fp {
        // Writing to a String can't fail.
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let fp = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
            0xdc, 0xfe, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];
        let s = to_hex(&fp);
        assert_eq!(s.len(), 2 + 64);
        assert!(s.starts_with("0x"));
        assert_eq!(parse_hex(&s).unwrap(), fp);
        // tolerate trailing newline and missing prefix
        assert_eq!(parse_hex(&format!("{}\n", &s[2..])).unwrap(), fp);
    }

    #[test]
    fn empty_r1cs_is_deterministic() {
        let r1cs = R1CS::new();
        let a = fingerprint(&r1cs, &[]).unwrap();
        let b = fingerprint(&r1cs, &[]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_changes_with_num_public_inputs() {
        let mut r1cs = R1CS::new();
        let a = fingerprint(&r1cs, &[]).unwrap();
        r1cs.num_public_inputs = 1;
        let b = fingerprint(&r1cs, &[]).unwrap();
        assert_ne!(a, b);
    }

    /// Completeness check on the matrix-encoding path: two R1CSes that
    /// agree on every shape field but differ in a single (A, B, or C)
    /// coefficient must produce different fingerprints. The matrix loop
    /// is straightforward enough that this is unlikely to regress, but
    /// having the explicit assertion makes future refactors loud.
    #[test]
    fn fingerprint_changes_with_matrix_entry() {
        use provekit_common::FieldElement;
        let one = FieldElement::from(1u64);
        let two = FieldElement::from(2u64);

        let mut a = R1CS::new();
        a.add_witnesses(3);
        a.add_constraint(&[(one, 2)], &[(one, 2)], &[(one, 1)]); // x · x = y

        let mut b = R1CS::new();
        b.add_witnesses(3);
        b.add_constraint(&[(two, 2)], &[(one, 2)], &[(one, 1)]); // (2x) · x = y — A[0][2] differs

        assert_ne!(fingerprint(&a, &[]).unwrap(), fingerprint(&b, &[]).unwrap());
    }

    #[test]
    fn fingerprint_changes_with_commitment_layout() {
        let r1cs = R1CS::new();
        let ci_a = CommitmentInfo {
            private_committed:               vec![5, 6, 7],
            public_and_commitment_committed: vec![1, 2],
            challenge_indices:               vec![10],
            nb_public_committed:             2,
        };
        let ci_b = CommitmentInfo {
            private_committed:               vec![5, 6, 8], // one index differs
            public_and_commitment_committed: vec![1, 2],
            challenge_indices:               vec![10],
            nb_public_committed:             2,
        };
        let a = fingerprint(&r1cs, std::slice::from_ref(&ci_a)).unwrap();
        let b = fingerprint(&r1cs, std::slice::from_ref(&ci_b)).unwrap();
        assert_ne!(a, b);
    }
}
