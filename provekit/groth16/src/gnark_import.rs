//! Read gnark Groth16 proving / verifying keys (BN254) from disk.
//!
//! Consumed by `cli prepare --groth16-pk-in / --groth16-vk-in` so the prepare
//! step can reuse keys produced by an external trusted-setup ceremony instead
//! of running the in-process [`crate::setup::setup`]. Shape validation against
//! the current R1CS happens later in [`crate::setup::setup_from_ceremony`];
//! this module only deals with the byte-level format.
//!
//! Wire format mirrors gnark's `(*ProvingKey).WriteTo` /
//! `(*VerifyingKey).WriteTo` in `backend/groth16/bn254/marshal.go`. Both
//! compressed and uncompressed point encodings are accepted (the gnark encoder
//! mixes them based on a per-point flag in the top 2 bits of byte 0), so this
//! reader works against stock trusted-setup output (`WriteTo`, compressed) and
//! against a patched ceremony that emits `WriteRawTo` (uncompressed) without
//! any flag change.
//!
//! Not handled here:
//! - Subgroup checks for G1 use cofactor-1 (any on-curve BN254 G1 point is in
//!   the prime-order subgroup). For G2 the cofactor is non-trivial, so each
//!   decoded G2 point is explicitly subgroup-checked.
//! - The deserialized [`crate::VerifyingKey`] has its `e_alpha_beta`,
//!   `g2_delta_neg`, `g2_gamma_neg` left as the zero placeholders. Provekit's
//!   [`crate::VerifyingKey::precompute`] writes them, and
//!   [`crate::setup::setup_from_ceremony`] is responsible for calling it
//!   *after* it has overridden `num_challenges_per_commitment` /
//!   `public_and_commitment_committed`. Calling `precompute` here would run it
//!   against the length-1 collapse-placeholder values for those two fields,
//!   which is wrong if `precompute` ever grows a dependency on them.

use {
    crate::{pedersen, ProvingKey, VerifyingKey},
    anyhow::{ensure, Context, Result},
    ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine},
    ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr},
    ark_ff::{AdditiveGroup, BigInt, Field, PrimeField, Zero},
    std::{
        fs::File,
        io::{BufReader, Read},
        path::Path,
    },
};

// gnark-crypto/ecc/bn254/marshal.go:26-30
const M_MASK: u8 = 0b11 << 6;
const M_UNCOMPRESSED: u8 = 0b00 << 6;
const M_COMPRESSED_INFINITY: u8 = 0b01 << 6;
const M_COMPRESSED_SMALLEST: u8 = 0b10 << 6;
const M_COMPRESSED_LARGEST: u8 = 0b11 << 6;

const FP_BYTES: usize = 32;
const G1_COMPRESSED: usize = 32;
const G1_UNCOMPRESSED: usize = 64;
const G2_COMPRESSED: usize = 64;
const G2_UNCOMPRESSED: usize = 128;

/// Upper bound on any length field read from the ceremony file (wire counts,
/// vector lengths, `[][]u64` outer/inner lengths). A malformed or malicious
/// file can declare arbitrarily large lengths; `vec![…; n]` /
/// `Vec::with_capacity(n)` against those lengths will OOM or panic. 2^30 is
/// comfortably above any real BN254 Groth16 circuit (~1B wires / vector
/// entries) while keeping a single bad header from requesting hundreds of GB.
const MAX_VEC_LEN: usize = 1 << 30;

fn bounded_len(n: u64, field: &str) -> Result<usize> {
    ensure!(
        n <= MAX_VEC_LEN as u64,
        "{field} length {n} exceeds sanity bound {MAX_VEC_LEN} — file is malformed or \
         attacker-supplied"
    );
    Ok(n as usize)
}

/// Undo gnark's `bitReverse(Z); Z = Z[:n-1]` ordering so the resulting slice
/// matches what Provekit's `setup::setup` writes (natural order, length n-1).
///
/// gnark builds Z as a length-`n` slice with entries `Z[i] = τⁱ · Z(τ)` for
/// `i ∈ [0, n-1)` and `Z[n-1] = 0`, then bit-reverses, then truncates. To
/// invert: pad back to length `n` (the dropped entry was 0 by construction —
/// its bit-reverse image is position n-1, which gnark truncated), apply the
/// permutation again (bit-reverse is its own inverse), and re-truncate.
fn unpermute_gnark_z<T: Clone + Default>(mut z: Vec<T>, domain_size: usize) -> Result<Vec<T>> {
    ensure!(
        domain_size.is_power_of_two() && domain_size >= 2,
        "domain_size {domain_size} is not a power of two ≥ 2"
    );
    let n_minus_1 = domain_size - 1;
    ensure!(
        z.len() == n_minus_1,
        "g1.Z length {} != expected n-1 ({})",
        z.len(),
        n_minus_1
    );
    z.push(T::default());
    bit_reverse_in_place(&mut z);
    z.pop();
    Ok(z)
}

/// In-place bit-reverse permutation on a power-of-two-length slice.
fn bit_reverse_in_place<T>(v: &mut [T]) {
    let n = v.len();
    if n <= 1 {
        return;
    }
    let bits = n.trailing_zeros() as usize;
    for i in 0..n {
        let j = bit_reverse_index(i, bits);
        if j > i {
            v.swap(i, j);
        }
    }
}

#[inline]
fn bit_reverse_index(mut x: usize, bits: usize) -> usize {
    let mut r = 0usize;
    for _ in 0..bits {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

/// Read a gnark Groth16 proving key from `path`.
///
/// Recomputes `non_inf_a` / `non_inf_b` from the deserialized
/// `infinity_a` / `infinity_b` bitmaps — gnark does not store those, but the
/// prover needs them.
pub fn read_proving_key(path: impl AsRef<Path>) -> Result<ProvingKey> {
    let path = path.as_ref();
    let file =
        File::open(path).with_context(|| format!("opening proving key {}", path.display()))?;
    let mut r = BufReader::new(file);
    read_proving_key_from(&mut r)
        .with_context(|| format!("parsing gnark proving key {}", path.display()))
}

/// Read a gnark Groth16 verifying key from `path`.
pub fn read_verifying_key(path: impl AsRef<Path>) -> Result<VerifyingKey> {
    let path = path.as_ref();
    let file =
        File::open(path).with_context(|| format!("opening verifying key {}", path.display()))?;
    let mut r = BufReader::new(file);
    read_verifying_key_from(&mut r)
        .with_context(|| format!("parsing gnark verifying key {}", path.display()))
}

// --- ProvingKey
// ---------------------------------------------------------------

fn read_proving_key_from<R: Read>(r: &mut R) -> Result<ProvingKey> {
    let (domain_size, domain_gen) = read_domain(r).context("domain")?;

    let g1_alpha = read_g1(r).context("g1.Alpha")?;
    let g1_beta = read_g1(r).context("g1.Beta")?;
    let g1_delta = read_g1(r).context("g1.Delta")?;
    let g1_a = read_g1_vec(r).context("g1.A")?;
    let g1_b = read_g1_vec(r).context("g1.B")?;
    let g1_z_gnark = read_g1_vec(r).context("g1.Z")?;
    // gnark stores Z in bit-reversed order
    // (`gnark/backend/groth16/bn254/mpcsetup/phase2.go:255-261`); Provekit's
    // prover expects natural order, since arkworks' IFFT outputs H in
    // natural order (`setup.rs:264-269`). `unpermute_gnark_z` does the
    // conversion — see its docstring for the algorithm.
    let g1_z = unpermute_gnark_z(g1_z_gnark, domain_size as usize).context("g1.Z bit-reverse")?;
    let g1_k = read_g1_vec(r).context("g1.K")?;
    let g2_beta = read_g2(r).context("g2.Beta")?;
    let g2_delta = read_g2(r).context("g2.Delta")?;
    let g2_b = read_g2_vec(r).context("g2.B")?;

    let nb_wires = bounded_len(read_u64_be(r).context("nbWires")?, "nbWires")?;
    let nb_infinity_a = read_u64_be(r).context("nbInfinityA")?;
    let nb_infinity_b = read_u64_be(r).context("nbInfinityB")?;
    // `nb_infinity_*` are cross-checked against `nb_wires` below (via the
    // `g1_a.len() + nb_infinity_a == nb_wires` ensures), so they are
    // transitively bounded — but guard the cast to usize explicitly so we
    // fail loud rather than via a subtraction wrap.
    ensure!(
        nb_infinity_a <= nb_wires as u64,
        "nbInfinityA ({nb_infinity_a}) > nbWires ({nb_wires})"
    );
    ensure!(
        nb_infinity_b <= nb_wires as u64,
        "nbInfinityB ({nb_infinity_b}) > nbWires ({nb_wires})"
    );

    let infinity_a = read_bool_vec(r, nb_wires).context("infinityA")?;
    let infinity_b = read_bool_vec(r, nb_wires).context("infinityB")?;

    // `g1_a` / `g1_b` only carry the non-infinity wires. Cross-check.
    let inf_a_count = infinity_a.iter().filter(|&&x| x).count() as u64;
    let inf_b_count = infinity_b.iter().filter(|&&x| x).count() as u64;
    ensure!(
        inf_a_count == nb_infinity_a,
        "infinityA count mismatch: header says {nb_infinity_a}, bitmap has {inf_a_count}"
    );
    ensure!(
        inf_b_count == nb_infinity_b,
        "infinityB count mismatch: header says {nb_infinity_b}, bitmap has {inf_b_count}"
    );
    ensure!(
        g1_a.len() + (nb_infinity_a as usize) == nb_wires,
        "g1.A length ({}) + nbInfinityA ({nb_infinity_a}) != nbWires ({nb_wires})",
        g1_a.len()
    );
    ensure!(
        g1_b.len() + (nb_infinity_b as usize) == nb_wires,
        "g1.B length ({}) + nbInfinityB ({nb_infinity_b}) != nbWires ({nb_wires})",
        g1_b.len()
    );
    ensure!(
        g2_b.len() + (nb_infinity_b as usize) == nb_wires,
        "g2.B length ({}) + nbInfinityB ({nb_infinity_b}) != nbWires ({nb_wires})",
        g2_b.len()
    );

    let non_inf_a: Vec<usize> = (0..nb_wires).filter(|&i| !infinity_a[i]).collect();
    let non_inf_b: Vec<usize> = (0..nb_wires).filter(|&i| !infinity_b[i]).collect();

    let nb_commitments = read_u32_be(r).context("nbCommitments")? as usize;
    let mut commitment_keys = Vec::with_capacity(nb_commitments);
    for i in 0..nb_commitments {
        commitment_keys.push(read_pedersen_pk(r).with_context(|| format!("commitment[{i}].pk"))?);
    }
    // Provekit's setup-time JSON exporter emits N gnark commitments per real
    // BSB22 commitment (entry [0] real, [1..N] dummies with empty Basis) to
    // force gnark to allocate N K-base slots — one per challenge wire — even
    // though the protocol uses only one Pedersen commitment. Collapse to a
    // single entry here so `setup_from_ceremony`'s `pk.commitment_keys.len()
    // == commitment_info.len()` check (`setup.rs:447-452`) passes, and so
    // the prover (`prover/src/lib.rs:544`, which only ever uses
    // `commitment_keys[0]`) does not waste memory on empty bases.
    //
    // We mirror `read_verifying_key_from`'s unconditional-truncation-to-[0]
    // rule rather than filtering by empty-basis, so PK and VK collapse stay
    // symmetric. The empty-basis property of dummies is then asserted
    // explicitly — if a future gnark version starts emitting non-empty
    // dummies, we fail loud here instead of silently mis-collapsing.
    let commitment_keys = if nb_commitments > 1 {
        for (i, ck) in commitment_keys.iter().enumerate().skip(1) {
            ensure!(
                ck.basis.is_empty() && ck.basis_exp_sigma.is_empty(),
                "ceremony pk commitment[{i}] has non-empty basis ({}) / basisExpSigma ({}); \
                 expected a dummy (entry [0] real, [1..] empty). gnark exporter format may have \
                 changed.",
                ck.basis.len(),
                ck.basis_exp_sigma.len()
            );
        }
        vec![commitment_keys.into_iter().next().context(
            "nb_commitments > 1 but commitment_keys empty after read loop — invariant violated",
        )?]
    } else {
        commitment_keys
    };

    Ok(ProvingKey {
        domain_size,
        domain_gen,
        g1_alpha,
        g1_beta,
        g1_delta,
        g1_a,
        g1_b,
        g1_k,
        g1_z,
        g2_beta,
        g2_delta,
        g2_b,
        infinity_a,
        infinity_b,
        nb_infinity_a,
        nb_infinity_b,
        non_inf_a,
        non_inf_b,
        commitment_keys,
    })
}

// --- VerifyingKey
// -------------------------------------------------------------

fn read_verifying_key_from<R: Read>(r: &mut R) -> Result<VerifyingKey> {
    let g1_alpha = read_g1(r).context("g1.Alpha")?;
    // gnark VK carries G1.Beta and G1.Delta; provekit's VK doesn't use them.
    let _g1_beta = read_g1(r).context("g1.Beta")?;
    let g2_beta = read_g2(r).context("g2.Beta")?;
    let g2_gamma = read_g2(r).context("g2.Gamma")?;
    let _g1_delta = read_g1(r).context("g1.Delta")?;
    let g2_delta = read_g2(r).context("g2.Delta")?;

    let g1_k = read_g1_vec(r).context("g1.K")?;

    let public_and_commitment_committed =
        read_u64_slice_slice_as_usize(r).context("publicAndCommitmentCommitted")?;

    let nb_commitments = read_u32_be(r).context("nbCommitments")? as usize;
    ensure!(
        public_and_commitment_committed.len() == nb_commitments,
        "publicAndCommitmentCommitted has {} entries, nbCommitments is {nb_commitments}",
        public_and_commitment_committed.len()
    );
    let mut commitment_keys = Vec::with_capacity(nb_commitments);
    for i in 0..nb_commitments {
        commitment_keys.push(read_pedersen_vk(r).with_context(|| format!("commitment[{i}].vk"))?);
    }

    // Collapse Provekit's N-dummy pattern down to one logical commitment.
    // Provekit's exporter emits N `Groth16Commitment` entries so gnark
    // allocates N K-base slots (one per challenge wire); the dummies are an
    // artifact of gnark's "1 K-base per commitment" sizing rule, not of
    // Provekit's protocol. The verifier (`verifier.rs:41-51`) enforces
    // `vk.commitment_keys.len() == vk.public_and_commitment_committed.len()`,
    // and `setup_from_ceremony` rewrites both `public_and_commitment_committed`
    // and `num_challenges_per_commitment` to length 1, so we need
    // `commitment_keys.len() == 1` here too. We keep entry [0] (the one tied
    // to the real Pedersen basis); the dummies carry no useful data the
    // protocol layer ever reads. Single-commitment files (nb_commitments==1)
    // are a no-op.
    let (commitment_keys, public_and_commitment_committed) = if nb_commitments > 1 {
        let ck0 = commitment_keys.into_iter().next().context(
            "nb_commitments > 1 but commitment_keys empty after read loop — invariant violated",
        )?;
        let pc0 = public_and_commitment_committed.into_iter().next().context(
            "nb_commitments > 1 but public_and_commitment_committed empty — invariant violated",
        )?;
        (vec![ck0], vec![pc0])
    } else {
        (commitment_keys, public_and_commitment_committed)
    };
    // After collapse, exactly one challenge per logical commitment. The
    // override in `setup_from_ceremony` writes the real N into this slot
    // before the verifier ever uses it.
    let num_challenges_per_commitment = vec![1usize; commitment_keys.len()];

    // NOTE: `e_alpha_beta`, `g2_delta_neg`, `g2_gamma_neg` are left as zero
    // placeholders here. `setup::setup_from_ceremony` calls `vk.precompute()`
    // after it has installed the real `num_challenges_per_commitment` and
    // `public_and_commitment_committed`, so any future precompute step that
    // touches those metadata fields sees the final values.
    let vk = VerifyingKey {
        g1_alpha,
        g1_k,
        g2_beta,
        g2_delta,
        g2_gamma,
        g2_delta_neg: G2Affine::zero(),
        g2_gamma_neg: G2Affine::zero(),
        e_alpha_beta: <ark_bn254::Bn254 as ark_ec::pairing::Pairing>::TargetField::ZERO,
        commitment_keys,
        public_and_commitment_committed,
        num_challenges_per_commitment,
    };
    Ok(vk)
}

// --- Pedersen blocks
// ----------------------------------------------------------

fn read_pedersen_pk<R: Read>(r: &mut R) -> Result<pedersen::ProvingKey> {
    let basis = read_g1_vec(r).context("basis")?;
    let basis_exp_sigma = read_g1_vec(r).context("basisExpSigma")?;
    ensure!(
        basis.len() == basis_exp_sigma.len(),
        "pedersen pk: basis ({}) and basisExpSigma ({}) length mismatch",
        basis.len(),
        basis_exp_sigma.len()
    );
    Ok(pedersen::ProvingKey {
        basis,
        basis_exp_sigma,
    })
}

fn read_pedersen_vk<R: Read>(r: &mut R) -> Result<pedersen::VerifyingKey> {
    let g = read_g2(r).context("g")?;
    let g_sigma_neg = read_g2(r).context("gSigmaNeg")?;
    Ok(pedersen::VerifyingKey { g, g_sigma_neg })
}

// --- FFT domain
// ---------------------------------------------------------------

/// gnark `fft.Domain.WriteTo` writes:
/// `Cardinality u64-BE, CardinalityInv Fr, Generator Fr, GeneratorInv Fr,
///  FrMultiplicativeGen Fr, FrMultiplicativeGenInv Fr, withPrecompute u8`.
/// Provekit only uses `Cardinality` and `Generator`; the rest is read past.
fn read_domain<R: Read>(r: &mut R) -> Result<(u64, Fr)> {
    let cardinality = read_u64_be(r)?;
    let _cardinality_inv = read_fr(r)?;
    let generator = read_fr(r)?;
    let _generator_inv = read_fr(r)?;
    let _fr_mul_gen = read_fr(r)?;
    let _fr_mul_gen_inv = read_fr(r)?;
    let mut wp = [0u8; 1];
    r.read_exact(&mut wp).context("withPrecompute")?;
    Ok((cardinality, generator))
}

// --- primitive readers
// --------------------------------------------------------

fn read_u32_be<R: Read>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_u64_be<R: Read>(r: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

/// Read one byte per bool (N total). gnark's encoder falls through to
/// `binary.Write` for `[]bool`, which writes one byte per element with no
/// slice-length prefix (the prefix is implicit in the preceding `nbWires`
/// u64).
fn read_bool_vec<R: Read>(r: &mut R, n: usize) -> Result<Vec<bool>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf.into_iter().map(|b| b != 0).collect())
}

/// 32B big-endian, canonical (rejects values `≥ r`).
fn read_fr<R: Read>(r: &mut R) -> Result<Fr> {
    let mut buf = [0u8; FP_BYTES];
    r.read_exact(&mut buf)?;
    fr_from_be_canonical(&buf)
}

fn fr_from_be_canonical(buf: &[u8; FP_BYTES]) -> Result<Fr> {
    let bi = bigint_from_be_bytes(buf);
    Fr::from_bigint(bi).context("non-canonical Fr element (≥ r)")
}

fn fq_from_be_canonical(buf: &[u8; FP_BYTES]) -> Result<Fq> {
    let bi = bigint_from_be_bytes(buf);
    Fq::from_bigint(bi).context("non-canonical Fp element (≥ p)")
}

/// 32-byte big-endian → `BigInt<4>` (arkworks stores limbs
/// little-endian-first).
fn bigint_from_be_bytes(buf: &[u8; FP_BYTES]) -> BigInt<4> {
    let mut limbs = [0u64; 4];
    // buf[0..8] is the highest 64-bit limb in BE-byte order; arkworks puts it in
    // limbs[3].
    limbs[3] = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    limbs[2] = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    limbs[1] = u64::from_be_bytes(buf[16..24].try_into().unwrap());
    limbs[0] = u64::from_be_bytes(buf[24..32].try_into().unwrap());
    BigInt::new(limbs)
}

// --- G1 reads
// -----------------------------------------------------------------

fn read_g1<R: Read>(r: &mut R) -> Result<G1Affine> {
    let mut buf = [0u8; G1_UNCOMPRESSED];
    r.read_exact(&mut buf[..G1_COMPRESSED])?;
    let flag = buf[0] & M_MASK;
    if flag == M_UNCOMPRESSED {
        r.read_exact(&mut buf[G1_COMPRESSED..G1_UNCOMPRESSED])?;
        decode_g1_uncompressed(&buf)
    } else {
        decode_g1_compressed(&buf[..G1_COMPRESSED])
    }
}

fn read_g1_vec<R: Read>(r: &mut R) -> Result<Vec<G1Affine>> {
    let len = bounded_len(read_u32_be(r)? as u64, "g1_vec")?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_g1(r)?);
    }
    Ok(out)
}

fn decode_g1_uncompressed(buf: &[u8; G1_UNCOMPRESSED]) -> Result<G1Affine> {
    // Top 2 bits hold the flag; the actual x bytes need them masked off.
    let mut x_bytes = [0u8; FP_BYTES];
    x_bytes.copy_from_slice(&buf[..FP_BYTES]);
    x_bytes[0] &= !M_MASK;
    let mut y_bytes = [0u8; FP_BYTES];
    y_bytes.copy_from_slice(&buf[FP_BYTES..]);

    // gnark's `RawBytes()` for infinity G1 writes `mUncompressed` (0b00) +
    // all-zero coordinates (see `gnark-crypto/ecc/bn254/marshal.go:826-834`);
    // arkworks represents the identity via the separate `infinity` flag, not
    // `(0, 0)` — `(0, 0)` is off-curve for `y² = x³ + 3`. Detect by the
    // canonical zero-byte encoding (after flag-bit removal) and route to
    // `G1Affine::zero()`.
    if x_bytes == [0u8; FP_BYTES] && y_bytes == [0u8; FP_BYTES] {
        return Ok(G1Affine::zero());
    }
    let x = fq_from_be_canonical(&x_bytes)?;
    let y = fq_from_be_canonical(&y_bytes)?;
    let p = G1Affine::new_unchecked(x, y);
    ensure!(p.is_on_curve(), "G1 uncompressed: point not on curve");
    // G1 cofactor is 1: on-curve ⇒ in-subgroup, no further check needed.
    Ok(p)
}

fn decode_g1_compressed(buf: &[u8]) -> Result<G1Affine> {
    debug_assert_eq!(buf.len(), G1_COMPRESSED);
    let flag = buf[0] & M_MASK;
    if flag == M_COMPRESSED_INFINITY {
        return Ok(G1Affine::zero());
    }
    ensure!(
        flag == M_COMPRESSED_SMALLEST || flag == M_COMPRESSED_LARGEST,
        "G1 compressed: invalid flag {flag:08b}"
    );
    let mut x_bytes = [0u8; FP_BYTES];
    x_bytes.copy_from_slice(buf);
    x_bytes[0] &= !M_MASK;
    let x = fq_from_be_canonical(&x_bytes)?;
    // y² = x³ + b, BN254 G1: b = 3
    let b = <ark_bn254::g1::Config as SWCurveConfig>::COEFF_B;
    let y_squared = x.square() * x + b;
    let mut y = y_squared
        .sqrt()
        .context("G1 compressed: no square root (x not on curve)")?;
    if fp_is_lex_largest(&y) != (flag == M_COMPRESSED_LARGEST) {
        y = -y;
    }
    let p = G1Affine::new_unchecked(x, y);
    ensure!(
        p.is_on_curve(),
        "G1 compressed: reconstructed point off curve"
    );
    Ok(p)
}

// --- G2 reads
// -----------------------------------------------------------------

fn read_g2<R: Read>(r: &mut R) -> Result<G2Affine> {
    let mut buf = [0u8; G2_UNCOMPRESSED];
    r.read_exact(&mut buf[..G2_COMPRESSED])?;
    let flag = buf[0] & M_MASK;
    if flag == M_UNCOMPRESSED {
        r.read_exact(&mut buf[G2_COMPRESSED..G2_UNCOMPRESSED])?;
        decode_g2_uncompressed(&buf)
    } else {
        decode_g2_compressed(&buf[..G2_COMPRESSED])
    }
}

fn read_g2_vec<R: Read>(r: &mut R) -> Result<Vec<G2Affine>> {
    let len = bounded_len(read_u32_be(r)? as u64, "g2_vec")?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_g2(r)?);
    }
    Ok(out)
}

/// gnark Fp2 byte layout: `[a1_be (32B), a0_be (32B)]` per coordinate, i.e.
/// the imaginary part comes first. So the full G2 uncompressed (128B) is
/// `[x.c1, x.c0, y.c1, y.c0]`.
fn decode_g2_uncompressed(buf: &[u8; G2_UNCOMPRESSED]) -> Result<G2Affine> {
    let mut x_c1 = [0u8; FP_BYTES];
    x_c1.copy_from_slice(&buf[0..32]);
    x_c1[0] &= !M_MASK;
    let mut x_c0 = [0u8; FP_BYTES];
    x_c0.copy_from_slice(&buf[32..64]);
    let mut y_c1 = [0u8; FP_BYTES];
    y_c1.copy_from_slice(&buf[64..96]);
    let mut y_c0 = [0u8; FP_BYTES];
    y_c0.copy_from_slice(&buf[96..128]);

    // gnark's `RawBytes()` for infinity G2 writes `mUncompressed` (0b00) +
    // all-zero coordinates (`gnark-crypto/ecc/bn254/marshal.go:1078-1086`).
    // arkworks uses a separate `infinity` flag, so detect by zero-byte
    // canonical form (after flag-bit removal) and route to `G2Affine::zero()`.
    if x_c0 == [0u8; FP_BYTES]
        && x_c1 == [0u8; FP_BYTES]
        && y_c0 == [0u8; FP_BYTES]
        && y_c1 == [0u8; FP_BYTES]
    {
        return Ok(G2Affine::zero());
    }

    let x = Fq2::new(fq_from_be_canonical(&x_c0)?, fq_from_be_canonical(&x_c1)?);
    let y = Fq2::new(fq_from_be_canonical(&y_c0)?, fq_from_be_canonical(&y_c1)?);
    let p = G2Affine::new_unchecked(x, y);
    ensure!(p.is_on_curve(), "G2 uncompressed: point not on curve");
    ensure!(
        p.is_in_correct_subgroup_assuming_on_curve(),
        "G2 uncompressed: subgroup check failed"
    );
    Ok(p)
}

fn decode_g2_compressed(buf: &[u8]) -> Result<G2Affine> {
    debug_assert_eq!(buf.len(), G2_COMPRESSED);
    let flag = buf[0] & M_MASK;
    if flag == M_COMPRESSED_INFINITY {
        return Ok(G2Affine::zero());
    }
    ensure!(
        flag == M_COMPRESSED_SMALLEST || flag == M_COMPRESSED_LARGEST,
        "G2 compressed: invalid flag {flag:08b}"
    );
    let mut x_c1 = [0u8; FP_BYTES];
    x_c1.copy_from_slice(&buf[0..32]);
    x_c1[0] &= !M_MASK;
    let mut x_c0 = [0u8; FP_BYTES];
    x_c0.copy_from_slice(&buf[32..64]);

    let x = Fq2::new(fq_from_be_canonical(&x_c0)?, fq_from_be_canonical(&x_c1)?);
    // y² = x³ + b', where b' = 3/(9+u) for BN254 G2.
    let b_twist = <ark_bn254::g2::Config as SWCurveConfig>::COEFF_B;
    let y_squared = x.square() * x + b_twist;
    let mut y = y_squared
        .sqrt()
        .context("G2 compressed: no square root (x not on curve)")?;
    if fq2_is_lex_largest(&y) != (flag == M_COMPRESSED_LARGEST) {
        y = -y;
    }
    let p = G2Affine::new_unchecked(x, y);
    ensure!(
        p.is_on_curve(),
        "G2 compressed: reconstructed point off curve"
    );
    ensure!(
        p.is_in_correct_subgroup_assuming_on_curve(),
        "G2 compressed: subgroup check failed"
    );
    Ok(p)
}

// --- lexicographic-largest helpers
// --------------------------------------------

/// gnark `fp.Element.LexicographicallyLargest`: `y > (p - y)` (canonical form).
fn fp_is_lex_largest(y: &Fq) -> bool {
    y.into_bigint() > (-*y).into_bigint()
}

/// gnark `e2.LexicographicallyLargest`: if `c1 != 0`, decide on `c1`; else
/// `c0`.
fn fq2_is_lex_largest(y: &Fq2) -> bool {
    if !y.c1.is_zero() {
        fp_is_lex_largest(&y.c1)
    } else {
        fp_is_lex_largest(&y.c0)
    }
}

// --- [][]u64 helper
// -----------------------------------------------------------

/// gnark encodes `[][]uint64` as: outer length u32-BE, then for each inner
/// `(inner length u32-BE, inner elements as u64-BE each)`.
/// (gnark-crypto `Encoder.writeUint64SliceSlice`.)
fn read_u64_slice_slice_as_usize<R: Read>(r: &mut R) -> Result<Vec<Vec<usize>>> {
    let outer = bounded_len(read_u32_be(r)? as u64, "u64_slice_slice outer")?;
    let mut result = Vec::with_capacity(outer);
    for _ in 0..outer {
        let inner = bounded_len(read_u32_be(r)? as u64, "u64_slice_slice inner")?;
        let mut v = Vec::with_capacity(inner);
        for _ in 0..inner {
            let u = read_u64_be(r)?;
            v.push(usize::try_from(u).context("u64 wire index does not fit in usize")?);
        }
        result.push(v);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `fp_is_lex_largest(y) != fp_is_lex_largest(-y)` for any nonzero y.
    /// Sanity check that our gnark-equivalent comparator agrees on sign.
    #[test]
    fn fp_lex_largest_distinguishes_y_and_neg_y() {
        use ark_ff::UniformRand;
        let mut rng = ark_std::test_rng();
        for _ in 0..16 {
            let y = Fq::rand(&mut rng);
            assert_ne!(fp_is_lex_largest(&y), fp_is_lex_largest(&-y));
        }
    }

    #[test]
    fn fq2_lex_largest_distinguishes_y_and_neg_y() {
        use ark_ff::UniformRand;
        let mut rng = ark_std::test_rng();
        for _ in 0..16 {
            let y = Fq2::rand(&mut rng);
            assert_ne!(fq2_is_lex_largest(&y), fq2_is_lex_largest(&-y));
        }
    }

    /// Round-trip a random G1 point through our compressed decoder by writing
    /// out gnark-format bytes manually, then reading them back.
    #[test]
    fn g1_compressed_roundtrip() {
        use {ark_ec::CurveGroup, ark_ff::UniformRand};
        let mut rng = ark_std::test_rng();
        for _ in 0..16 {
            let p = ark_bn254::G1Projective::rand(&mut rng).into_affine();
            let bytes = encode_g1_compressed_gnark(&p);
            let decoded = decode_g1_compressed(&bytes).expect("decode");
            assert_eq!(decoded, p);
        }
    }

    #[test]
    fn g2_compressed_roundtrip() {
        use {ark_ec::CurveGroup, ark_ff::UniformRand};
        let mut rng = ark_std::test_rng();
        for _ in 0..16 {
            let p = ark_bn254::G2Projective::rand(&mut rng).into_affine();
            let bytes = encode_g2_compressed_gnark(&p);
            let decoded = decode_g2_compressed(&bytes).expect("decode");
            assert_eq!(decoded, p);
        }
    }

    /// Same shape as gnark's `(*G1Affine).Bytes()`.
    fn encode_g1_compressed_gnark(p: &G1Affine) -> [u8; G1_COMPRESSED] {
        let mut out = [0u8; G1_COMPRESSED];
        if p.is_zero() {
            out[0] = M_COMPRESSED_INFINITY;
            return out;
        }
        let x = p.x().unwrap();
        let mut x_bytes = [0u8; FP_BYTES];
        let bi = x.into_bigint();
        let bytes = bi.0;
        // limbs[3] is the high BE limb
        x_bytes[0..8].copy_from_slice(&bytes[3].to_be_bytes());
        x_bytes[8..16].copy_from_slice(&bytes[2].to_be_bytes());
        x_bytes[16..24].copy_from_slice(&bytes[1].to_be_bytes());
        x_bytes[24..32].copy_from_slice(&bytes[0].to_be_bytes());
        out.copy_from_slice(&x_bytes);
        let flag = if fp_is_lex_largest(&p.y().unwrap()) {
            M_COMPRESSED_LARGEST
        } else {
            M_COMPRESSED_SMALLEST
        };
        out[0] |= flag;
        out
    }

    fn encode_g2_compressed_gnark(p: &G2Affine) -> [u8; G2_COMPRESSED] {
        let mut out = [0u8; G2_COMPRESSED];
        if p.is_zero() {
            out[0] = M_COMPRESSED_INFINITY;
            return out;
        }
        let x = p.x().unwrap();
        write_fp_be(&mut out[0..32], &x.c1);
        write_fp_be(&mut out[32..64], &x.c0);
        let flag = if fq2_is_lex_largest(&p.y().unwrap()) {
            M_COMPRESSED_LARGEST
        } else {
            M_COMPRESSED_SMALLEST
        };
        out[0] |= flag;
        out
    }

    fn write_fp_be(dst: &mut [u8], v: &Fq) {
        let bytes = v.into_bigint().0;
        dst[0..8].copy_from_slice(&bytes[3].to_be_bytes());
        dst[8..16].copy_from_slice(&bytes[2].to_be_bytes());
        dst[16..24].copy_from_slice(&bytes[1].to_be_bytes());
        dst[24..32].copy_from_slice(&bytes[0].to_be_bytes());
    }
}
