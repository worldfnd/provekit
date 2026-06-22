//! bn254 public-input instance hashing.
//!
//! Hashes base-field public inputs to a single field element under a runtime
//! [`HashConfig`], binding them to the Fiat-Shamir transcript. This is the
//! field-welded body behind [`crate::Bn254Field`]'s
//! [`provekit_common::FieldHash::hash_public_inputs`].

use {
    crate::bytes::field_to_bytes_le,
    ark_ff::{BigInt, PrimeField},
    provekit_common::{FieldElement, HashConfig},
    std::sync::LazyLock,
};

/// Domain-separation tag for public-input instance binding.
///
/// **Protocol-visible constant.** This string is absorbed into the SHA-256,
/// Keccak, and BLAKE3 hashes used for public-input commitments; for Poseidon2
/// it is reduced to a [`FieldElement`] via [`PUBLIC_INPUTS_DST_FE`] and
/// prepended to the hash input. Changing it invalidates every proof generated
/// under those configurations. The `V1` suffix reserves an unambiguous
/// upgrade path (`_V2`, …) for any future construction change.
///
/// [`HashConfig::Skyscraper`] intentionally omits the tag — its
/// empty-input-returns-0 output is part of the stable Skyscraper proof
/// format, and introducing a tag would break every deployed Skyscraper
/// proof.
const PUBLIC_INPUTS_DST: &[u8] = b"PROVEKIT_PUBLIC_INPUTS_V1";
static PUBLIC_INPUTS_DST_FE: LazyLock<FieldElement> = LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    FieldElement::from_le_bytes_mod_order(&Sha256::digest(PUBLIC_INPUTS_DST))
});

/// Hashes `elements` into a single field element under `config`.
///
/// Binds public inputs to the Fiat-Shamir transcript instance: the prover
/// absorbs this value and the verifier recomputes and compares. Deterministic
/// in `(config, elements)`.
#[inline]
#[must_use]
pub(crate) fn hash_field_elements(config: HashConfig, elements: &[FieldElement]) -> FieldElement {
    match config {
        HashConfig::Skyscraper => hash_skyscraper(elements),
        HashConfig::Sha256 => hash_digest::<sha2::Sha256>(PUBLIC_INPUTS_DST, elements),
        HashConfig::Keccak => hash_digest::<sha3::Keccak256>(PUBLIC_INPUTS_DST, elements),
        HashConfig::Blake3 => hash_blake3(PUBLIC_INPUTS_DST, elements),
        HashConfig::Poseidon2 => hash_poseidon2(elements),
    }
}

/// Pairwise Skyscraper compression; empty input hashes to 0. Not
/// domain-separated (see [`PUBLIC_INPUTS_DST`]).
#[inline]
fn hash_skyscraper(elements: &[FieldElement]) -> FieldElement {
    #[inline]
    fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
        let out = skyscraper::simple::compress(l.into_bigint().0, r.into_bigint().0);
        FieldElement::new(BigInt(out))
    }

    let zero = FieldElement::from(0u64);
    match elements {
        [] => zero,
        [x] => compress(*x, zero),
        [first, rest @ ..] => rest.iter().copied().fold(*first, compress),
    }
}

/// DST-tagged [`sha2::digest::Digest`] hash (SHA-256, Keccak-256) over
/// `elements`.
///
/// The final [`FieldElement::from_le_bytes_mod_order`] reduction introduces
/// ~2⁻²⁵⁴ bias — negligible for FS instance binding, but this is not a
/// uniform field sampler.
#[inline]
fn hash_digest<D>(dst: &[u8], elements: &[FieldElement]) -> FieldElement
where
    D: sha2::digest::Digest,
{
    let mut hasher = D::new();
    hasher.update(dst);
    for fe in elements {
        hasher.update(field_to_bytes_le(*fe));
    }
    FieldElement::from_le_bytes_mod_order(&hasher.finalize())
}

/// Poseidon2 one-shot hash over `elements` (including empty input).
///
/// Prepends [`PUBLIC_INPUTS_DST_FE`] as the first absorbed field element
/// to provide **role** domain-separation (distinct from Merkle/FS usages of
/// the same Poseidon2 permutation). The capacity-lane IV inside
/// [`poseidon2::poseidon2_hash`] separately provides **length** domain-
/// separation, so the two combined mirror what SHA/Keccak/BLAKE3 get via
/// the raw [`PUBLIC_INPUTS_DST`] byte prefix.
#[inline]
fn hash_poseidon2(elements: &[FieldElement]) -> FieldElement {
    let mut tagged = Vec::with_capacity(elements.len() + 1);
    tagged.push(*PUBLIC_INPUTS_DST_FE);
    tagged.extend_from_slice(elements);
    poseidon2::poseidon2_hash(&tagged)
}

/// BLAKE3 analogue of [`hash_digest`]. BLAKE3 does not implement
/// [`sha2::digest::Digest`] without the optional `traits-preview` feature, so
/// it gets its own small helper.
#[inline]
fn hash_blake3(dst: &[u8], elements: &[FieldElement]) -> FieldElement {
    let mut hasher = blake3::Hasher::new();
    hasher.update(dst);
    for fe in elements {
        hasher.update(&field_to_bytes_le(*fe));
    }
    FieldElement::from_le_bytes_mod_order(hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use {super::*, proptest::prelude::*};

    const ALL_CONFIGS: [HashConfig; 5] = [
        HashConfig::Skyscraper,
        HashConfig::Sha256,
        HashConfig::Keccak,
        HashConfig::Blake3,
        HashConfig::Poseidon2,
    ];

    fn fe(n: u64) -> FieldElement {
        FieldElement::from(n)
    }

    fn vals(v: &[u64]) -> Vec<FieldElement> {
        v.iter().copied().map(fe).collect()
    }

    fn hash(config: HashConfig, v: &[u64]) -> FieldElement {
        hash_field_elements(config, &vals(v))
    }

    fn hash_bytes(config: HashConfig, v: &[u64]) -> [u8; 32] {
        field_to_bytes_le(hash_field_elements(config, &vals(v)))
    }

    // --- determinism ---

    #[test]
    fn hash_is_deterministic_for_all_configs() {
        for config in ALL_CONFIGS {
            assert_eq!(
                hash(config, &[1, 2, 3]),
                hash(config, &[1, 2, 3]),
                "{config:?}: hash must be deterministic"
            );
        }
    }

    #[test]
    fn hash_bytes_is_deterministic_for_all_configs() {
        for config in ALL_CONFIGS {
            assert_eq!(
                hash_bytes(config, &[42]),
                hash_bytes(config, &[42]),
                "{config:?}: hash_bytes must be deterministic"
            );
        }
    }

    #[test]
    fn hash_bytes_is_le_serialization_of_hash() {
        for config in ALL_CONFIGS {
            assert_eq!(
                hash_bytes(config, &[7, 13]),
                field_to_bytes_le(hash(config, &[7, 13])),
                "{config:?}: hash_bytes must equal LE(hash())"
            );
        }
    }

    // --- empty input ---

    #[test]
    fn skyscraper_empty_returns_zero() {
        // Transcript-visible back-compat: Skyscraper hashes [] to 0.
        assert_eq!(hash(HashConfig::Skyscraper, &[]), FieldElement::from(0u64),);
    }

    #[test]
    fn empty_input_is_deterministic_for_all_configs() {
        for config in ALL_CONFIGS {
            assert_eq!(
                hash(config, &[]),
                hash(config, &[]),
                "{config:?}: empty hash must be deterministic"
            );
        }
    }

    // --- cross-variant isolation ---

    #[test]
    fn different_configs_produce_different_hashes() {
        // Non-trivial input so Skyscraper's empty-→-0 behaviour doesn't collide
        // with any other variant's H(DST) mod p by coincidence.
        let hashes: Vec<_> = ALL_CONFIGS.iter().map(|&c| hash(c, &[1, 2])).collect();
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "{:?} and {:?} must produce different hashes for the same input",
                    ALL_CONFIGS[i], ALL_CONFIGS[j],
                );
            }
        }
    }

    // --- input sensitivity ---

    #[test]
    fn hash_depends_on_order_for_all_configs() {
        for config in ALL_CONFIGS {
            assert_ne!(
                hash(config, &[1, 2]),
                hash(config, &[2, 1]),
                "{config:?}: hash must be order-sensitive"
            );
        }
    }

    #[test]
    fn hash_depends_on_values_for_all_configs() {
        for config in ALL_CONFIGS {
            assert_ne!(
                hash(config, &[1, 2, 3]),
                hash(config, &[1, 2, 4]),
                "{config:?}: hash must differ when values differ"
            );
        }
    }

    // --- no ambient state ---

    #[test]
    fn hashing_is_independent_of_prior_calls() {
        // Pins the no-global-state contract: an intervening call with a
        // different config must not influence a later call.
        let first = hash(HashConfig::Sha256, &[55, 89]);
        let _ = hash(HashConfig::Keccak, &[55, 89]);
        let third = hash(HashConfig::Sha256, &[55, 89]);
        assert_eq!(
            first, third,
            "Sha256 result must not depend on an intervening Keccak call"
        );
    }

    // --- known-answer tests (regression pins) ---
    //
    // Byte-exact outputs of `hash_field_elements(config, ..)` in LE bytes for
    // fixed inputs. Any change to the encoding (DST, per-element serialization,
    // mod-reduction, Skyscraper compression order) will fail these and must be
    // a deliberate, reviewed format change.

    #[test]
    fn kat_empty_skyscraper() {
        // Skyscraper on empty input is 0 by construction; no DST.
        assert_eq!(
            hash_bytes(HashConfig::Skyscraper, &[]),
            [0u8; 32],
            "Skyscraper empty-input KAT drift"
        );
    }

    #[test]
    fn kat_one_two_skyscraper() {
        assert_eq!(
            hash_bytes(HashConfig::Skyscraper, &[1, 2]),
            [
                0x7c, 0x38, 0x2a, 0x25, 0xa9, 0x25, 0x53, 0x1f, 0x7e, 0x26, 0xa8, 0xab, 0xdc, 0x91,
                0x1a, 0x03, 0x95, 0x2a, 0x46, 0x9e, 0xfb, 0xb5, 0x71, 0xe9, 0x86, 0x3f, 0x1c, 0xcd,
                0x56, 0x7e, 0xe6, 0x2d,
            ],
            "Skyscraper [1, 2] KAT drift"
        );
    }

    #[test]
    fn kat_empty_sha256() {
        assert_eq!(
            hash_bytes(HashConfig::Sha256, &[]),
            KAT_EMPTY_SHA256,
            "SHA-256 empty-input KAT drift"
        );
    }

    #[test]
    fn kat_one_two_sha256() {
        assert_eq!(
            hash_bytes(HashConfig::Sha256, &[1, 2]),
            KAT_ONE_TWO_SHA256,
            "SHA-256 [1, 2] KAT drift"
        );
    }

    #[test]
    fn kat_empty_keccak() {
        assert_eq!(
            hash_bytes(HashConfig::Keccak, &[]),
            KAT_EMPTY_KECCAK,
            "Keccak-256 empty-input KAT drift"
        );
    }

    #[test]
    fn kat_one_two_keccak() {
        assert_eq!(
            hash_bytes(HashConfig::Keccak, &[1, 2]),
            KAT_ONE_TWO_KECCAK,
            "Keccak-256 [1, 2] KAT drift"
        );
    }

    #[test]
    fn kat_empty_blake3() {
        assert_eq!(
            hash_bytes(HashConfig::Blake3, &[]),
            KAT_EMPTY_BLAKE3,
            "BLAKE3 empty-input KAT drift"
        );
    }

    #[test]
    fn kat_one_two_blake3() {
        assert_eq!(
            hash_bytes(HashConfig::Blake3, &[1, 2]),
            KAT_ONE_TWO_BLAKE3,
            "BLAKE3 [1, 2] KAT drift"
        );
    }

    #[test]
    fn kat_empty_poseidon2() {
        // Non-zero: even with no user inputs, the DST field element is
        // prepended and the capacity-lane IV still permutes.
        assert_eq!(
            hash_bytes(HashConfig::Poseidon2, &[]),
            KAT_EMPTY_POSEIDON2,
            "Poseidon2 empty-input KAT drift"
        );
    }

    #[test]
    fn kat_one_two_poseidon2() {
        assert_eq!(
            hash_bytes(HashConfig::Poseidon2, &[1, 2]),
            KAT_ONE_TWO_POSEIDON2,
            "Poseidon2 [1, 2] KAT drift"
        );
    }

    // Frozen outputs. Regenerate only for a deliberate, reviewed format change.

    const KAT_EMPTY_SHA256: [u8; 32] = [
        0xc6, 0xa2, 0x48, 0x23, 0x44, 0xd4, 0x29, 0xf5, 0x53, 0x37, 0xc3, 0xb6, 0x87, 0xb5, 0xc3,
        0x54, 0x47, 0x5c, 0x7c, 0x7f, 0x17, 0xac, 0x26, 0xeb, 0x47, 0x92, 0x78, 0x00, 0x11, 0xfe,
        0xa0, 0x26,
    ];
    const KAT_ONE_TWO_SHA256: [u8; 32] = [
        0x0f, 0x7b, 0x4c, 0xec, 0x9b, 0x45, 0x3f, 0xe5, 0x2f, 0xf4, 0x32, 0x96, 0x96, 0x60, 0xd2,
        0xd8, 0x92, 0x5e, 0x7c, 0x34, 0xdd, 0x27, 0x59, 0x05, 0x7f, 0xc0, 0xf2, 0x73, 0x43, 0x53,
        0x76, 0x1d,
    ];
    const KAT_EMPTY_KECCAK: [u8; 32] = [
        0xb2, 0x2f, 0xf9, 0x91, 0x4f, 0xaf, 0xbd, 0xd0, 0x3c, 0x4f, 0xa2, 0x7a, 0xb0, 0x8a, 0x34,
        0x5f, 0x0e, 0x1c, 0x62, 0x53, 0xf4, 0xc0, 0x02, 0x37, 0x2b, 0xaa, 0x50, 0x3c, 0x82, 0xb1,
        0x2d, 0x23,
    ];
    const KAT_ONE_TWO_KECCAK: [u8; 32] = [
        0xb1, 0xe0, 0x10, 0xfa, 0x01, 0x19, 0xcf, 0x35, 0x85, 0xac, 0x34, 0xb3, 0xdb, 0xb0, 0x11,
        0x17, 0x57, 0xa9, 0x63, 0xff, 0x8d, 0x3c, 0x76, 0xc9, 0xf7, 0xc6, 0x79, 0xb0, 0xfb, 0xf1,
        0x41, 0x16,
    ];
    const KAT_EMPTY_BLAKE3: [u8; 32] = [
        0x7b, 0x01, 0x61, 0xea, 0x26, 0xb6, 0x36, 0xbc, 0x69, 0x23, 0xf3, 0x87, 0x7d, 0x4d, 0xca,
        0xb8, 0xf7, 0xa9, 0xb4, 0x8d, 0x38, 0x56, 0x01, 0x13, 0x93, 0x57, 0xa0, 0x55, 0x37, 0x0c,
        0xda, 0x27,
    ];
    const KAT_ONE_TWO_BLAKE3: [u8; 32] = [
        0x84, 0x08, 0x71, 0x4e, 0xb3, 0xb2, 0x8e, 0x8f, 0xd6, 0xb5, 0xd0, 0x3d, 0x35, 0x99, 0x08,
        0x4e, 0x47, 0x7d, 0x1f, 0xf9, 0xf5, 0x79, 0xc1, 0x46, 0xb4, 0x28, 0x84, 0xa5, 0x6b, 0xc5,
        0xa5, 0x25,
    ];
    // Poseidon2([]) = poseidon2_hash([PUBLIC_INPUTS_DST_FE]) in LE bytes —
    // the empty-input case is still a one-element absorb of the DST tag
    // (role-DS) with the length-IV set for `n = 1`. The DST field element
    // is derived as SHA256(PUBLIC_INPUTS_DST) reduced mod p.
    const KAT_EMPTY_POSEIDON2: [u8; 32] = [
        0x88, 0x8d, 0xd0, 0xb7, 0xbb, 0x12, 0xee, 0x46, 0xf0, 0x73, 0x14, 0x15, 0x2c, 0xec, 0x94,
        0xf8, 0x5f, 0x5a, 0xbd, 0x58, 0xe3, 0xfd, 0x8a, 0x96, 0xb5, 0x18, 0x4c, 0x23, 0xd8, 0x7d,
        0xf3, 0x01,
    ];
    const KAT_ONE_TWO_POSEIDON2: [u8; 32] = [
        0x54, 0xfa, 0xbf, 0xce, 0x1b, 0xe4, 0xbb, 0xe9, 0x92, 0xb0, 0x6a, 0x42, 0xeb, 0xf7, 0x2d,
        0xf4, 0x47, 0x8a, 0x2d, 0xb1, 0x9c, 0x5f, 0x35, 0xbf, 0x7c, 0x62, 0xba, 0x9d, 0x65, 0x67,
        0x01, 0x22,
    ];

    // --- property tests ---

    fn any_hash_config() -> impl Strategy<Value = HashConfig> {
        prop_oneof![
            Just(HashConfig::Skyscraper),
            Just(HashConfig::Sha256),
            Just(HashConfig::Keccak),
            Just(HashConfig::Blake3),
            Just(HashConfig::Poseidon2),
        ]
    }

    proptest! {
        #[test]
        fn prop_hash_is_deterministic(
            config in any_hash_config(),
            inputs in prop::collection::vec(any::<u64>(), 0..32),
        ) {
            let v = vals(&inputs);
            prop_assert_eq!(
                hash_field_elements(config, &v),
                hash_field_elements(config, &v)
            );
        }

        #[test]
        fn prop_hash_bytes_is_deterministic(
            config in any_hash_config(),
            inputs in prop::collection::vec(any::<u64>(), 0..32),
        ) {
            let v = vals(&inputs);
            prop_assert_eq!(
                field_to_bytes_le(hash_field_elements(config, &v)),
                field_to_bytes_le(hash_field_elements(config, &v))
            );
        }

        #[test]
        fn prop_distinct_inputs_distinct_hashes(
            config in any_hash_config(),
            a in prop::collection::vec(any::<u64>(), 1..32),
            b in prop::collection::vec(any::<u64>(), 1..32),
        ) {
            prop_assume!(a != b);
            prop_assert_ne!(
                hash_field_elements(config, &vals(&a)),
                hash_field_elements(config, &vals(&b))
            );
        }
    }
}
