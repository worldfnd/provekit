//! Runtime hash configuration selection for ProveKit.
//!
//! Runtime selection of hash algorithms used for:
//! - Merkle tree commitments (via WHIR's `EngineId`)
//! - the Fiat-Shamir transcript sponge (via [`crate::TranscriptSponge`])
//! - public-input instance binding ([`HashConfig::hash_field_elements`])

use {
    crate::{utils::field_to_bytes_le, FieldElement},
    serde::{Deserialize, Serialize},
    std::fmt,
};
#[cfg(feature = "bn254")]
use {
    ark_ff::{BigInt, PrimeField},
    std::sync::LazyLock,
};

/// Hash algorithm configuration that can be selected at runtime.
///
/// Each variant selects the same algorithm for Merkle commitments,
/// Fiat-Shamir sponge, and public-input binding. Skyscraper and Poseidon2
/// are BN254-only constructions and exist only under the `bn254` feature;
/// the default is Skyscraper under `bn254` and [`Self::Sha256`] under
/// `goldilocks`.
///
/// Serialization is hand-written (see the `Serialize`/`Deserialize` impls
/// below) rather than derived: the derive numbers variants positionally, so
/// `#[cfg]`-gating Skyscraper/Poseidon2 out of a goldilocks build silently
/// shifts every remaining index (`Sha256` becomes `0` instead of `1`, etc.),
/// which would let a postcard/CBOR-encoded config written by one field build
/// decode as the wrong variant under the other. The manual impls route binary
/// formats through the field-independent [`Self::to_byte`]/[`Self::from_byte`]
/// (the same stable byte used in proof-file headers) and human-readable
/// formats through [`Self::name`]/[`Self::parse`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum HashConfig {
    #[cfg(feature = "bn254")]
    #[default]
    Skyscraper,

    #[cfg_attr(all(feature = "goldilocks", not(feature = "bn254")), default)]
    Sha256,

    Keccak,

    Blake3,

    #[cfg(feature = "bn254")]
    Poseidon2,
}

impl Serialize for HashConfig {
    /// Human-readable formats (JSON, …) get the canonical name string; binary
    /// formats (postcard, CBOR, …) get the field-independent [`Self::to_byte`]
    /// value. Under `bn254` both forms are byte-identical to the old derive,
    /// so existing proofs/schemes are unaffected.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.name())
        } else {
            serializer.serialize_u8(self.to_byte())
        }
    }
}

impl<'de> Deserialize<'de> for HashConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        if deserializer.is_human_readable() {
            let name = String::deserialize(deserializer)?;
            Self::parse(&name)
                .ok_or_else(|| D::Error::custom(format!("unknown hash configuration: {name:?}")))
        } else {
            let byte = u8::deserialize(deserializer)?;
            Self::from_byte(byte)
                .ok_or_else(|| D::Error::custom(format!("invalid hash configuration byte: {byte}")))
        }
    }
}

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
///
/// Regression trip-wires: the KATs in `witness::tests` freeze the
/// byte-exact output of each variant under this constant.
const PUBLIC_INPUTS_DST: &[u8] = b"PROVEKIT_PUBLIC_INPUTS_V1";
#[cfg(feature = "bn254")]
static PUBLIC_INPUTS_DST_FE: LazyLock<FieldElement> = LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    FieldElement::from_le_bytes_mod_order(&Sha256::digest(PUBLIC_INPUTS_DST))
});

impl HashConfig {
    /// Returns the canonical name of this hash configuration.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "bn254")]
            Self::Skyscraper => "skyscraper",
            Self::Sha256 => "sha256",
            Self::Keccak => "keccak",
            Self::Blake3 => "blake3",
            #[cfg(feature = "bn254")]
            Self::Poseidon2 => "poseidon2",
        }
    }

    /// Returns the WHIR 2.0 engine ID for this hash configuration.
    #[must_use]
    pub fn engine_id(&self) -> whir::engines::EngineId {
        match self {
            #[cfg(feature = "bn254")]
            Self::Skyscraper => crate::skyscraper::SKYSCRAPER,
            Self::Sha256 => whir::hash::SHA2,
            Self::Keccak => whir::hash::KECCAK,
            Self::Blake3 => whir::hash::BLAKE3,
            #[cfg(feature = "bn254")]
            Self::Poseidon2 => crate::poseidon2::POSEIDON2,
        }
    }

    /// Converts hash configuration to a single byte for binary file headers.
    #[must_use]
    pub fn to_byte(&self) -> u8 {
        match self {
            #[cfg(feature = "bn254")]
            Self::Skyscraper => 0,
            Self::Sha256 => 1,
            Self::Keccak => 2,
            Self::Blake3 => 3,
            #[cfg(feature = "bn254")]
            Self::Poseidon2 => 4,
        }
    }

    /// Converts a byte from binary file header to hash configuration.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            #[cfg(feature = "bn254")]
            0 => Some(Self::Skyscraper),
            1 => Some(Self::Sha256),
            2 => Some(Self::Keccak),
            3 => Some(Self::Blake3),
            #[cfg(feature = "bn254")]
            4 => Some(Self::Poseidon2),
            _ => None,
        }
    }

    /// Parses a hash configuration from a string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            #[cfg(feature = "bn254")]
            "skyscraper" | "sky" => Some(Self::Skyscraper),
            "sha256" | "sha" | "sha-256" => Some(Self::Sha256),
            "keccak" | "keccak-256" | "shake" => Some(Self::Keccak),
            "blake3" | "blake-3" | "b3" => Some(Self::Blake3),
            #[cfg(feature = "bn254")]
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
            #[cfg(feature = "bn254")]
            Self::Skyscraper => hash_skyscraper(elements),
            Self::Sha256 => hash_digest::<sha2::Sha256>(PUBLIC_INPUTS_DST, elements),
            Self::Keccak => hash_digest::<sha3::Keccak256>(PUBLIC_INPUTS_DST, elements),
            Self::Blake3 => hash_blake3(PUBLIC_INPUTS_DST, elements),
            #[cfg(feature = "bn254")]
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
        #[cfg(feature = "bn254")]
        const VALID: &str = "skyscraper, sha256, keccak, blake3, poseidon2";
        #[cfg(all(feature = "goldilocks", not(feature = "bn254")))]
        const VALID: &str = "sha256, keccak, blake3";
        Self::parse(s).ok_or_else(|| {
            format!(
                "Invalid hash configuration: '{}'. Valid options: {VALID}",
                s
            )
        })
    }
}

/// Pairwise Skyscraper compression; empty input hashes to 0. Not
/// domain-separated (see [`PUBLIC_INPUTS_DST`]).
#[cfg(feature = "bn254")]
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

/// Reduces a hash digest into a [`FieldElement`] (BN254: straight
/// little-endian mod-p reduction; ~2⁻²⁵⁴ bias — negligible for FS instance
/// binding, but not a uniform field sampler).
#[cfg(feature = "bn254")]
#[inline]
fn digest_to_field(digest: &[u8]) -> FieldElement {
    FieldElement::from_le_bytes_mod_order(digest)
}

/// Reduces a hash digest into a [`FieldElement`] by spreading it across all
/// three coordinates of the Goldilocks cubic extension.
///
/// The digest is split into three contiguous chunks, each reduced mod the
/// ~64-bit Goldilocks base prime, so the image is the full ~192-bit cubic
/// extension rather than the ~64-bit base subfield a single reduction would
/// produce. This value is *both* the Fiat-Shamir instance tag and the absorbed
/// public-inputs hash the verifier recomputes and compares.
///
/// Why spread: the collision resistance of a binding hash is the birthday
/// bound over its image (~2^(bits/2)), not the image size. A base-subfield
/// image (~2⁶⁴ values) would give only ~2³² resistance; the full extension
/// (~2¹⁹²) gives ~2⁹⁶, itself bounded by the 256-bit digest's own ~2¹²⁸. ~2⁹⁶
/// is still below the 128-bit WHIR target, but this tag is *defense-in-depth*,
/// not the sole binding: public-input binding is enforced independently by the
/// verifier's direct value check (`verify_public_input_binding`, soundness
/// error ~deg/|F|), so soundness does not rest on this hash's collision
/// resistance. Like the BN254 sibling, this is a binding hash, not a uniform
/// field sampler.
#[cfg(all(feature = "goldilocks", not(feature = "bn254")))]
#[inline]
fn digest_to_field(digest: &[u8]) -> FieldElement {
    use {ark_ff::PrimeField, whir::algebra::fields::Field64};
    let chunk = digest.len().div_ceil(3);
    let c0 = Field64::from_le_bytes_mod_order(&digest[..chunk.min(digest.len())]);
    let c1 = Field64::from_le_bytes_mod_order(digest.get(chunk..2 * chunk).unwrap_or(&[]));
    let c2 = Field64::from_le_bytes_mod_order(digest.get(2 * chunk..).unwrap_or(&[]));
    FieldElement::new(c0, c1, c2)
}

/// DST-tagged [`sha2::digest::Digest`] hash (SHA-256, Keccak-256) over
/// `elements`, reduced to a field element via [`digest_to_field`].
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
    digest_to_field(&hasher.finalize())
}

/// Poseidon2 one-shot hash over `elements` (including empty input).
///
/// Prepends [`PUBLIC_INPUTS_DST_FE`] as the first absorbed field element
/// to provide **role** domain-separation (distinct from Merkle/FS usages of
/// the same Poseidon2 permutation). The capacity-lane IV inside
/// [`poseidon2::poseidon2_hash`] separately provides **length** domain-
/// separation, so the two combined mirror what SHA/Keccak/BLAKE3 get via
/// the raw [`PUBLIC_INPUTS_DST`] byte prefix.
#[cfg(feature = "bn254")]
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
    digest_to_field(hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All known variants. If a new variant is added to `HashConfig`, this
    /// list must be updated — causing the exhaustiveness tests below to fail
    /// until `from_byte` / `to_byte` are also updated.
    #[cfg(feature = "bn254")]
    const ALL_VARIANTS: &[HashConfig] = &[
        HashConfig::Skyscraper,
        HashConfig::Sha256,
        HashConfig::Keccak,
        HashConfig::Blake3,
        HashConfig::Poseidon2,
    ];
    #[cfg(all(feature = "goldilocks", not(feature = "bn254")))]
    const ALL_VARIANTS: &[HashConfig] =
        &[HashConfig::Sha256, HashConfig::Keccak, HashConfig::Blake3];

    /// Binary serde must encode the field-independent [`HashConfig::to_byte`]
    /// value, NOT serde's positional variant index. Otherwise cfg-gating
    /// Skyscraper/Poseidon2 out of a goldilocks build shifts `Sha256` from 1
    /// to 0, silently colliding with Skyscraper's byte across field builds.
    #[test]
    fn binary_serde_is_field_independent_to_byte() {
        for &v in ALL_VARIANTS {
            let bytes = postcard::to_allocvec(&v).unwrap();
            assert_eq!(
                bytes,
                vec![v.to_byte()],
                "{v:?}: postcard must equal to_byte()"
            );
            let back: HashConfig = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(back, v, "{v:?}: postcard roundtrip");
        }
        // Pinned: these bytes must be identical in every field build.
        assert_eq!(postcard::to_allocvec(&HashConfig::Sha256).unwrap(), vec![
            1u8
        ]);
        assert_eq!(postcard::to_allocvec(&HashConfig::Keccak).unwrap(), vec![
            2u8
        ]);
        assert_eq!(postcard::to_allocvec(&HashConfig::Blake3).unwrap(), vec![
            3u8
        ]);
    }

    /// Human-readable serde uses the canonical name string (stable across
    /// fields) and round-trips, including the legacy aliases via `parse`.
    #[test]
    fn human_readable_serde_is_canonical_name() {
        for &v in ALL_VARIANTS {
            let json = serde_json::to_string(&v).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", v.name()),
                "{v:?}: json must be name()"
            );
            let back: HashConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v, "{v:?}: json roundtrip");
        }
        assert_eq!(
            serde_json::to_string(&HashConfig::Sha256).unwrap(),
            "\"sha256\""
        );
        let aliased: HashConfig = serde_json::from_str("\"sha-256\"").unwrap();
        assert_eq!(aliased, HashConfig::Sha256, "legacy alias must still parse");
    }

    /// A goldilocks build must *reject* binary bytes for variants it does not
    /// have (0 = Skyscraper, 4 = Poseidon2) rather than silently misdecode —
    /// this is the cross-field-substitution guard the derive lacked.
    #[cfg(all(feature = "goldilocks", not(feature = "bn254")))]
    #[test]
    fn binary_serde_rejects_bn254_only_bytes() {
        assert!(
            postcard::from_bytes::<HashConfig>(&[0u8]).is_err(),
            "byte 0 (Skyscraper) must be rejected, not decoded as Sha256"
        );
        assert!(
            postcard::from_bytes::<HashConfig>(&[4u8]).is_err(),
            "byte 4 (Poseidon2) must be rejected"
        );
    }

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
        // 5 is the first byte beyond the full (bn254) variant space.
        assert!(
            HashConfig::from_byte(5).is_none(),
            "from_byte(5) should be None"
        );
        assert!(
            HashConfig::from_byte(u8::MAX).is_none(),
            "from_byte(255) should be None"
        );
    }

    /// Goldilocks builds must reject the BN254-only header bytes
    /// (0 = Skyscraper, 4 = Poseidon2) gracefully rather than panic.
    #[cfg(all(feature = "goldilocks", not(feature = "bn254")))]
    #[test]
    fn from_byte_rejects_bn254_only_headers() {
        assert!(HashConfig::from_byte(0).is_none(), "byte 0 is Skyscraper");
        assert!(HashConfig::from_byte(4).is_none(), "byte 4 is Poseidon2");
    }

    #[cfg(feature = "bn254")]
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
