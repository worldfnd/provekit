//! Public-input instance hashing.
//!
//! Hashes base-field public inputs to a single extension element under a
//! runtime [`HashConfig`], binding them to the Fiat-Shamir transcript.

use {
    ark_ff::PrimeField,
    ark_serialize::CanonicalSerialize,
    provekit_common::HashConfig,
    whir::algebra::fields::{Field64, Field64_3},
};

/// Domain-separation tag for public-input instance binding.
///
/// **Protocol-visible constant.** Absorbed into the SHA-256, Keccak, and BLAKE3
/// hashes used for public-input commitments; changing it invalidates every
/// proof generated under those configurations. The `V1` suffix reserves an
/// unambiguous upgrade path (`_V2`, …) for any future construction change.
const PUBLIC_INPUTS_DST: &[u8] = b"PROVEKIT_PUBLIC_INPUTS_V1";

/// Hashes `elements` into a single extension element under `config`.
///
/// Binds public inputs to the Fiat-Shamir transcript instance: the prover
/// absorbs this value and the verifier recomputes and compares. Deterministic
/// in `(config, elements)`.
///
/// # Panics
/// Panics for [`HashConfig::Skyscraper`] and [`HashConfig::Poseidon2`], which
/// operate on 256-bit field elements and are not defined over this field.
#[inline]
#[must_use]
pub(crate) fn hash_field_elements<F: CanonicalSerialize>(
    config: HashConfig,
    elements: &[F],
) -> Field64_3 {
    match config {
        HashConfig::Sha256 => hash_digest::<sha2::Sha256, F>(PUBLIC_INPUTS_DST, elements),
        HashConfig::Keccak => hash_digest::<sha3::Keccak256, F>(PUBLIC_INPUTS_DST, elements),
        HashConfig::Blake3 => hash_blake3(PUBLIC_INPUTS_DST, elements),
        HashConfig::Skyscraper | HashConfig::Poseidon2 => {
            panic!("HashConfig::{config:?} operates on 256-bit elements and is unsupported here")
        }
    }
}

/// Canonical little-endian bytes of one field element.
#[inline]
fn elem_bytes<F: CanonicalSerialize>(fe: &F) -> Vec<u8> {
    let mut out = Vec::with_capacity(fe.compressed_size());
    // Serializing to a `Vec` sink cannot fail.
    let _ = fe.serialize_compressed(&mut out);
    out
}

/// Reduces a hash digest to an extension element by spreading it across all
/// three coordinates of the cubic extension.
///
/// The digest is split into three contiguous chunks, each reduced mod the
/// ~64-bit base prime, so the image is the full ~192-bit cubic extension rather
/// than the ~64-bit base subfield a single reduction would produce. This is a
/// binding tag, not a uniform field sampler.
#[inline]
pub(crate) fn digest_to_field(digest: &[u8]) -> Field64_3 {
    let chunk = digest.len().div_ceil(3);
    let c0 = Field64::from_le_bytes_mod_order(digest.get(..chunk).unwrap_or(digest));
    let c1 = Field64::from_le_bytes_mod_order(digest.get(chunk..2 * chunk).unwrap_or(&[]));
    let c2 = Field64::from_le_bytes_mod_order(digest.get(2 * chunk..).unwrap_or(&[]));
    Field64_3::new(c0, c1, c2)
}

/// DST-tagged [`sha2::digest::Digest`] hash (SHA-256, Keccak-256) over
/// `elements`, reduced via [`digest_to_field`].
#[inline]
fn hash_digest<D, F>(dst: &[u8], elements: &[F]) -> Field64_3
where
    D: sha2::digest::Digest,
    F: CanonicalSerialize,
{
    let mut hasher = D::new();
    hasher.update(dst);
    for fe in elements {
        hasher.update(elem_bytes(fe));
    }
    digest_to_field(&hasher.finalize())
}

/// BLAKE3 analogue of [`hash_digest`]. BLAKE3 does not implement
/// [`sha2::digest::Digest`] without the optional `traits-preview` feature, so
/// it gets its own small helper.
#[inline]
fn hash_blake3<F: CanonicalSerialize>(dst: &[u8], elements: &[F]) -> Field64_3 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(dst);
    for fe in elements {
        hasher.update(&elem_bytes(fe));
    }
    digest_to_field(hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use {super::*, crate::bytes::field_to_bytes_le, ark_ff::Field};

    const SUPPORTED: [HashConfig; 3] = [HashConfig::Sha256, HashConfig::Keccak, HashConfig::Blake3];

    fn vals(v: &[u64]) -> Vec<Field64_3> {
        v.iter().copied().map(Field64_3::from).collect()
    }

    fn hash(config: HashConfig, v: &[u64]) -> Field64_3 {
        hash_field_elements(config, &vals(v))
    }

    #[test]
    fn hash_is_deterministic() {
        for config in SUPPORTED {
            assert_eq!(
                hash(config, &[1, 2, 3]),
                hash(config, &[1, 2, 3]),
                "{config:?}"
            );
            assert_eq!(hash(config, &[]), hash(config, &[]), "{config:?} empty");
        }
    }

    #[test]
    fn hash_is_order_sensitive() {
        for config in SUPPORTED {
            assert_ne!(hash(config, &[1, 2]), hash(config, &[2, 1]), "{config:?}");
        }
    }

    #[test]
    fn hash_is_value_sensitive() {
        for config in SUPPORTED {
            assert_ne!(
                hash(config, &[1, 2, 3]),
                hash(config, &[1, 2, 4]),
                "{config:?}"
            );
        }
    }

    #[test]
    fn distinct_configs_distinct_hashes() {
        let hashes: Vec<_> = SUPPORTED.iter().map(|&c| hash(c, &[1, 2])).collect();
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "{:?} vs {:?}",
                    SUPPORTED[i], SUPPORTED[j]
                );
            }
        }
    }

    #[test]
    fn spread_fills_all_three_coordinates() {
        // A non-trivial input lands outside the base subfield (c1, c2 not both 0),
        // confirming the digest spread reaches the full cubic extension.
        let h = hash(HashConfig::Sha256, &[1, 2, 3]);
        let coords = h.to_base_prime_field_elements().collect::<Vec<_>>();
        assert_eq!(coords.len(), 3);
        assert!(
            coords[1] != Field64::from(0u64) || coords[2] != Field64::from(0u64),
            "binding hash collapsed into the base subfield"
        );
    }

    // Frozen outputs (LE bytes of the hash) for fixed inputs. Any change to the
    // encoding (DST, per-element serialization, digest spread) fails these and
    // must be a deliberate, reviewed format change.
    #[test]
    fn kat_one_two_sha256() {
        assert_eq!(
            field_to_bytes_le(hash(HashConfig::Sha256, &[1, 2])),
            KAT_ONE_TWO_SHA256
        );
    }

    #[test]
    fn kat_empty_sha256() {
        assert_eq!(
            field_to_bytes_le(hash(HashConfig::Sha256, &[])),
            KAT_EMPTY_SHA256
        );
    }

    const KAT_ONE_TWO_SHA256: [u8; 24] = [
        131, 95, 205, 190, 68, 78, 13, 206, 7, 169, 28, 14, 140, 41, 211, 19, 89, 89, 231, 3, 187,
        207, 164, 81,
    ];
    const KAT_EMPTY_SHA256: [u8; 24] = [
        49, 169, 159, 226, 44, 164, 90, 5, 24, 184, 147, 146, 122, 173, 128, 130, 53, 228, 237, 18,
        113, 109, 221, 55,
    ];
}
