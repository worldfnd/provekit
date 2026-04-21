//! Runtime hash configuration selection for ProveKit.
//!
//! Runtime selection of hash algorithms used for:
//! - Merkle tree commitments (via WHIR's `EngineId`)
//! - the Fiat-Shamir transcript sponge (via [`crate::TranscriptSponge`])
//! - public-input instance binding ([`HashConfig::hash_field_elements`])

use {
    crate::FieldElement,
    ark_ff::{BigInt, BigInteger, PrimeField},
    serde::{Deserialize, Serialize},
    std::fmt,
};

/// Hash algorithm configuration that can be selected at runtime.
///
/// Each variant selects the same algorithm for Merkle commitments,
/// Fiat-Shamir sponge, and public-input binding. [`Self::Skyscraper`] is the
/// default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashConfig {
    #[default]
    #[serde(alias = "sky")]
    Skyscraper,

    #[serde(alias = "sha", alias = "sha-256")]
    Sha256,

    #[serde(alias = "keccak-256", alias = "shake")]
    Keccak,

    #[serde(alias = "blake-3", alias = "b3")]
    Blake3,

    #[serde(alias = "pos2", alias = "p2")]
    Poseidon2,
}

/// Domain-separation tag for public-input instance binding.
///
/// **Protocol-visible constant.** This string is absorbed into the SHA-256,
/// Keccak, and BLAKE3 hashes used for public-input commitments; changing it
/// invalidates every proof generated under those configurations. The `V1`
/// suffix reserves an unambiguous upgrade path (`_V2`, …) for any future
/// construction change.
///
/// [`HashConfig::Skyscraper`] intentionally omits the tag — its
/// empty-input-returns-0 output is part of the stable Skyscraper proof
/// format, and introducing a tag would break every deployed Skyscraper
/// proof.
///
/// Regression trip-wires: the KATs in `witness::tests` freeze the
/// byte-exact output of each variant under this constant.
const PUBLIC_INPUTS_DST: &[u8] = b"PROVEKIT_PUBLIC_INPUTS_V1";

impl HashConfig {
    /// Returns the canonical name of this hash configuration.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Skyscraper => "skyscraper",
            Self::Sha256 => "sha256",
            Self::Keccak => "keccak",
            Self::Blake3 => "blake3",
            Self::Poseidon2 => "poseidon2",
        }
    }

    /// Returns the WHIR 2.0 engine ID for this hash configuration.
    #[must_use]
    pub fn engine_id(&self) -> whir::engines::EngineId {
        match self {
            Self::Skyscraper => crate::skyscraper::SKYSCRAPER,
            Self::Sha256 => whir::hash::SHA2,
            Self::Keccak => whir::hash::KECCAK,
            Self::Blake3 => whir::hash::BLAKE3,
            Self::Poseidon2 => crate::poseidon2::POSEIDON2,
        }
    }

    /// Converts hash configuration to a single byte for binary file headers.
    #[must_use]
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::Skyscraper => 0,
            Self::Sha256 => 1,
            Self::Keccak => 2,
            Self::Blake3 => 3,
            Self::Poseidon2 => 4,
        }
    }

    /// Converts a byte from binary file header to hash configuration.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Skyscraper),
            1 => Some(Self::Sha256),
            2 => Some(Self::Keccak),
            3 => Some(Self::Blake3),
            4 => Some(Self::Poseidon2),
            _ => None,
        }
    }

    /// Parses a hash configuration from a string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "skyscraper" | "sky" => Some(Self::Skyscraper),
            "sha256" | "sha" | "sha-256" => Some(Self::Sha256),
            "keccak" | "keccak-256" | "shake" => Some(Self::Keccak),
            "blake3" | "blake-3" | "b3" => Some(Self::Blake3),
            "poseidon2" | "pos2" | "p2" => Some(Self::Poseidon2),
            _ => None,
        }
    }

    /// Hashes `elements` into a single field element under this configuration.
    ///
    /// Binds public inputs to the Fiat-Shamir transcript instance: the prover
    /// absorbs this value and the verifier recomputes and compares.
    /// Deterministic in `(self, elements)`; any change in either produces a
    /// different output with overwhelming probability.
    ///
    /// # Examples
    ///
    /// ```
    /// # use provekit_common::{FieldElement, HashConfig};
    /// let h = HashConfig::Sha256
    ///     .hash_field_elements(&[FieldElement::from(1u64), FieldElement::from(2u64)]);
    /// # let _ = h;
    /// ```
    #[inline]
    #[must_use]
    pub fn hash_field_elements(self, elements: &[FieldElement]) -> FieldElement {
        match self {
            Self::Skyscraper => hash_skyscraper(elements),
            Self::Sha256 => hash_digest::<sha2::Sha256>(PUBLIC_INPUTS_DST, elements),
            Self::Keccak => hash_digest::<sha3::Keccak256>(PUBLIC_INPUTS_DST, elements),
            Self::Blake3 => hash_blake3(PUBLIC_INPUTS_DST, elements),
            Self::Poseidon2 => hash_poseidon2(elements),
        }
    }
}

impl fmt::Display for HashConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for HashConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| {
            format!(
                "Invalid hash configuration: '{}'. Valid options: skyscraper, sha256, keccak, \
                 blake3, poseidon2",
                s
            )
        })
    }
}

/// Serializes a BN254 field element to its canonical 32-byte little-endian
/// representation.
#[inline]
pub(crate) fn fe_to_bytes_le(fe: &FieldElement) -> [u8; 32] {
    let bytes = fe.into_bigint().to_bytes_le();
    debug_assert!(
        bytes.len() <= 32,
        "field element serialized to more than 32 bytes"
    );
    let mut result = [0u8; 32];
    result[..bytes.len()].copy_from_slice(&bytes);
    result
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
        hasher.update(fe_to_bytes_le(fe));
    }
    FieldElement::from_le_bytes_mod_order(&hasher.finalize())
}

/// Poseidon2 one-shot hash over `elements` (including empty input).
///
/// Does NOT use [`PUBLIC_INPUTS_DST`] — length domain-separation is handled
/// by the capacity-lane IV (`n * 2^64`), so `poseidon2_hash([])` already
/// produces a distinct non-zero output for the empty case.
#[inline]
fn hash_poseidon2(elements: &[FieldElement]) -> FieldElement {
    poseidon2::poseidon2_hash(elements)
}

/// BLAKE3 analogue of [`hash_digest`]. BLAKE3 does not implement
/// [`sha2::digest::Digest`] without the optional `traits-preview` feature, so
/// it gets its own small helper.
#[inline]
fn hash_blake3(dst: &[u8], elements: &[FieldElement]) -> FieldElement {
    let mut hasher = blake3::Hasher::new();
    hasher.update(dst);
    for fe in elements {
        hasher.update(&fe_to_bytes_le(fe));
    }
    FieldElement::from_le_bytes_mod_order(hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All known variants. If a new variant is added to `HashConfig`, this
    /// list must be updated — causing the exhaustiveness tests below to fail
    /// until `from_byte` / `to_byte` are also updated.
    const ALL_VARIANTS: &[HashConfig] = &[
        HashConfig::Skyscraper,
        HashConfig::Sha256,
        HashConfig::Keccak,
        HashConfig::Blake3,
        HashConfig::Poseidon2,
    ];

    #[test]
    fn from_byte_roundtrips_with_to_byte() {
        for &variant in ALL_VARIANTS {
            let byte = variant.to_byte();
            let recovered = HashConfig::from_byte(byte)
                .unwrap_or_else(|| panic!("from_byte({byte}) returned None for {variant:?}"));
            assert_eq!(variant, recovered, "roundtrip failed for {variant:?}");
        }
    }

    #[test]
    fn from_byte_returns_none_for_invalid() {
        let first_invalid = ALL_VARIANTS.len() as u8;
        assert!(
            HashConfig::from_byte(first_invalid).is_none(),
            "from_byte({first_invalid}) should be None"
        );
        assert!(
            HashConfig::from_byte(u8::MAX).is_none(),
            "from_byte(255) should be None"
        );
    }

    #[test]
    fn to_byte_values_are_contiguous_from_zero() {
        let mut bytes: Vec<u8> = ALL_VARIANTS.iter().map(|v| v.to_byte()).collect();
        bytes.sort();
        let expected: Vec<u8> = (0..ALL_VARIANTS.len() as u8).collect();
        assert_eq!(bytes, expected, "to_byte values should be 0..N contiguous");
    }

    #[test]
    fn from_byte_covers_all_variants() {
        let recovered: Vec<HashConfig> = (0..=u8::MAX).filter_map(HashConfig::from_byte).collect();
        for &variant in ALL_VARIANTS {
            assert!(
                recovered.contains(&variant),
                "{variant:?} is not reachable via from_byte"
            );
        }
        assert_eq!(
            recovered.len(),
            ALL_VARIANTS.len(),
            "from_byte maps to more variants than ALL_VARIANTS lists"
        );
    }
}
