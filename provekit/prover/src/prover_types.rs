//! Backend-aware Prover enum.
//!
//! Lives in `provekit_prover` (not `provekit_common`) so the Groth16 variant
//! can hold a typed `provekit_groth16::ProvingKey` directly. Common cannot
//! import `provekit_groth16` without creating a dependency cycle, so the union
//! type that knows about every backend is rooted here.

// `MaybeHashAware` lives behind `provekit_common::file::io`, which is gated to
// non-wasm targets. The only consumer of the `MaybeHashAware for Prover` impl
// is `pkp_io`, which is itself non-wasm-gated, so confine both to that target.
#[cfg(not(target_arch = "wasm32"))]
use provekit_common::{file::MaybeHashAware, HashConfig};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
use {
    acir::circuit::Program,
    provekit_common::{
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        MavrosProver, NoirElement, NoirProver, R1CS,
    },
    serde::{Deserialize, Deserializer, Serialize, Serializer},
};

/// BSB22 commitment info for ProveKit's Groth16 backend.
///
/// One Pedersen commitment over all private w1 wires,
/// producing multiple challenges via `hash_to_fr_multi`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Groth16CommitmentInfo {
    /// Indices of public wires hashed with the commitment.
    pub public_committed:  Vec<usize>,
    /// Indices of private/internal wires committed to via Pedersen.
    pub private_committed: Vec<usize>,
    /// Wire indices where the derived challenge values are stored.
    pub challenge_indices: Vec<usize>,
}

/// Source of the Groth16 proving key bytes: either an in-memory owned
/// [`provekit_groth16::ProvingKey`] (legacy zstd `.pkp` path) or an mmap-backed
/// [`provekit_groth16::MmapProvingKey`] that points directly at file pages
/// (rapidsnark-style mmap `.pkp` path). Wrapping the mmap variant in `Arc`
/// keeps `Groth16Prover: Clone` cheap (just bumps the Arc refcount, never
/// re-mmaps).
///
/// Serialization for both variants emits zero bytes — the PK is always loaded
/// out-of-band by the matching reader (`pkp_io::read_pkp` for owned,
/// `pkp_mmap_io::read_pkp_mmap` for mmap). This preserves the existing
/// postcard wire format byte-for-byte.
#[derive(Debug, Clone)]
pub enum Groth16PkSource {
    /// Standard owned proving key. Loaded from the legacy zstd `.pkp` path,
    /// or built fresh by `provekit_groth16::setup`.
    Owned(provekit_groth16::ProvingKey),
    /// Mmap-backed proving key. Loaded from the mmap `.pkp` path. Slices
    /// borrow into the file mapping; the `Arc` ensures the mapping outlives
    /// every clone of this prover.
    #[cfg(not(target_arch = "wasm32"))]
    Mmap(Arc<provekit_groth16::MmapProvingKey>),
}

impl Default for Groth16PkSource {
    fn default() -> Self {
        Groth16PkSource::Owned(provekit_groth16::ProvingKey::empty())
    }
}

// Wire format: zero bytes, identical to the existing `ProvingKey` Serialize
// impl. The actual PK bytes live elsewhere (zstd-stream tail for the legacy
// path, mmap section bodies for the mmap path).
impl Serialize for Groth16PkSource {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for Groth16PkSource {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let _: () = Deserialize::deserialize(de)?;
        Ok(Groth16PkSource::default())
    }
}

/// Borrowed view of a Groth16 proving key. Returned by
/// [`Groth16PkSource::view`] so the proving code can be written once against
/// slices and run against either the owned or the mmap-backed source.
pub struct Groth16PkView<'a> {
    pub domain_size:     u64,
    pub g1_alpha:        ark_bn254::G1Affine,
    pub g1_beta:         ark_bn254::G1Affine,
    pub g1_delta:        ark_bn254::G1Affine,
    pub g2_beta:         ark_bn254::G2Affine,
    pub g2_delta:        ark_bn254::G2Affine,
    pub g1_a:            &'a [ark_bn254::G1Affine],
    pub g1_b:            &'a [ark_bn254::G1Affine],
    pub g1_k:            &'a [ark_bn254::G1Affine],
    pub g1_z:            &'a [ark_bn254::G1Affine],
    pub g2_b:            &'a [ark_bn254::G2Affine],
    pub infinity_a:      &'a [bool],
    pub infinity_b:      &'a [bool],
    /// Precomputed wire indices where `A(τ) != 0` (the complement of
    /// `infinity_a`). Built at setup time for owned PKs, at mmap-load time
    /// for mmap PKs. Lets `prove_ar_bs_bs1` build the MSM input by direct
    /// indexing instead of re-filtering on every prove call.
    pub non_inf_a:       &'a [usize],
    /// Twin of `non_inf_a` for the B side.
    pub non_inf_b:       &'a [usize],
    /// One view per BSB22 commitment. Borrows basis arrays out of either
    /// owned `pedersen::ProvingKey`s (legacy path) or mmap'd file pages
    /// (rapidsnark-style raw layout), with no allocation of the bases
    /// either way. The outer `Vec` allocation is one entry per
    /// commitment — a few hundred bytes for typical circuits.
    pub commitment_keys: Vec<provekit_groth16::pedersen::ProvingKeyView<'a>>,
}

impl Groth16PkSource {
    pub fn view(&self) -> Groth16PkView<'_> {
        match self {
            Groth16PkSource::Owned(pk) => Groth16PkView {
                domain_size:     pk.domain_size,
                g1_alpha:        pk.g1_alpha,
                g1_beta:         pk.g1_beta,
                g1_delta:        pk.g1_delta,
                g2_beta:         pk.g2_beta,
                g2_delta:        pk.g2_delta,
                g1_a:            &pk.g1_a,
                g1_b:            &pk.g1_b,
                g1_k:            &pk.g1_k,
                g1_z:            &pk.g1_z,
                g2_b:            &pk.g2_b,
                infinity_a:      &pk.infinity_a,
                infinity_b:      &pk.infinity_b,
                non_inf_a:       &pk.non_inf_a,
                non_inf_b:       &pk.non_inf_b,
                commitment_keys: pk.commitment_keys.iter().map(|ck| ck.view()).collect(),
            },
            #[cfg(not(target_arch = "wasm32"))]
            Groth16PkSource::Mmap(m) => Groth16PkView {
                domain_size:     m.domain_size,
                g1_alpha:        m.g1_alpha,
                g1_beta:         m.g1_beta,
                g1_delta:        m.g1_delta,
                g2_beta:         m.g2_beta,
                g2_delta:        m.g2_delta,
                g1_a:            m.g1_a(),
                g1_b:            m.g1_b(),
                g1_k:            m.g1_k(),
                g1_z:            m.g1_z(),
                g2_b:            m.g2_b(),
                infinity_a:      m.infinity_a(),
                infinity_b:      m.infinity_b(),
                non_inf_a:       &m.non_inf_a,
                non_inf_b:       &m.non_inf_b,
                commitment_keys: m.commitment_keys.iter().map(|ck| ck.view()).collect(),
            },
        }
    }

    /// Borrow the inner owned `ProvingKey`, if this source owns one. Returns
    /// `None` for the mmap-backed variant (that path uses `view()` to access
    /// borrowed fields).
    pub fn as_owned(&self) -> Option<&provekit_groth16::ProvingKey> {
        match self {
            Groth16PkSource::Owned(pk) => Some(pk),
            #[cfg(not(target_arch = "wasm32"))]
            Groth16PkSource::Mmap(_) => None,
        }
    }

    /// Mutable access to the inner owned `ProvingKey`. Used by `pkp_io` when
    /// streaming arkworks bytes into the placeholder PK created by
    /// `Groth16PkSource::default()` after postcard returns. Errors if the
    /// source is mmap-backed.
    pub fn as_owned_mut(&mut self) -> Option<&mut provekit_groth16::ProvingKey> {
        match self {
            Groth16PkSource::Owned(pk) => Some(pk),
            #[cfg(not(target_arch = "wasm32"))]
            Groth16PkSource::Mmap(_) => None,
        }
    }
}

impl From<provekit_groth16::ProvingKey> for Groth16PkSource {
    fn from(pk: provekit_groth16::ProvingKey) -> Self {
        Groth16PkSource::Owned(pk)
    }
}

/// Groth16 prover: holds R1CS, witness builders, and the typed proving key.
///
/// `groth16_pk` is a [`Groth16PkSource`] — either an owned
/// [`provekit_groth16::ProvingKey`] or an mmap-backed
/// [`provekit_groth16::MmapProvingKey`]; both source variants serialize as
/// zero bytes so the postcard wire format for that field is stable.
///
/// As of `PROVER_VERSION = (1, 5)`, `r1cs` and `commitment_info` are
/// `#[serde(skip)]` and travel outside the postcard blob:
/// - Legacy zstd path: appended as length-prefixed postcard chunks after the
///   arkworks-encoded PK (see `pkp_io::write_pkp`).
/// - Mmap path: raw-byte chunks following the PK section table (see
///   `mmap_pk::write_r1cs_chunk` / `write_commitment_info_chunk`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Prover {
    pub program:                Program<NoirElement>,
    /// R1CS constraint matrices. As of PROVER_VERSION (1, 5) this field is
    /// NOT included in the postcard blob. The legacy zstd path
    /// length-prefixes its postcard bytes after the PK in the same zstd
    /// stream. The mmap path stores its three sparse matrices + interner
    /// as raw mmap sections (memcpy'd into owned `Vec`s on load — see
    /// `provekit_groth16::mmap_pk`). Default during postcard deserialize
    /// is `R1CS::new()`; both readers then populate the real value.
    #[serde(skip)]
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    /// Typed Groth16 proving key (owned or mmap-backed).
    pub groth16_pk:             Groth16PkSource,
    /// BSB22 commitment metadata (empty if circuit has no commitments).
    /// Same treatment as `r1cs` above: omitted from postcard, transported
    /// by the format-specific reader (length-prefixed postcard for the
    /// legacy zstd path; raw mmap sections for the mmap path).
    #[serde(skip)]
    pub commitment_info:        Vec<Groth16CommitmentInfo>,
}

// INVARIANT: Variant order is wire-format-critical (postcard uses positional
// discriminants). Do not reorder, cfg-gate, or insert variants without
// verifying cross-target deserialization (native <-> WASM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Prover {
    Noir(NoirProver),
    Mavros(MavrosProver),
    Groth16(Groth16Prover),
}

impl Prover {
    /// Convert a compilation output into the on-disk prover format.
    pub fn from_noir_proof_scheme(scheme: provekit_common::NoirProofScheme) -> Self {
        use provekit_common::NoirProofScheme;
        match scheme {
            NoirProofScheme::Noir(d) => Prover::Noir(NoirProver {
                hash_config:            d.hash_config,
                program:                d.program,
                r1cs:                   d.r1cs,
                split_witness_builders: d.split_witness_builders,
                witness_generator:      d.witness_generator,
                whir_for_witness:       d.whir_for_witness,
            }),
            NoirProofScheme::Mavros(d) => Prover::Mavros(MavrosProver {
                abi:                d.abi,
                num_public_inputs:  d.num_public_inputs,
                whir_for_witness:   d.whir_for_witness,
                witgen_binary:      d.witgen_binary,
                ad_binary:          d.ad_binary,
                constraints_layout: d.constraints_layout,
                witness_layout:     d.witness_layout,
                hash_config:        d.hash_config,
            }),
        }
    }

    pub fn abi(&self) -> &noirc_abi::Abi {
        match self {
            Prover::Noir(p) => p.witness_generator.abi(),
            Prover::Mavros(p) => &p.abi,
            Prover::Groth16(p) => p.witness_generator.abi(),
        }
    }

    pub fn size(&self) -> (usize, usize) {
        match self {
            Prover::Noir(p) => (p.r1cs.num_constraints(), p.r1cs.num_witnesses()),
            Prover::Mavros(p) => (
                p.constraints_layout.algebraic_size,
                p.witness_layout.algebraic_size,
            ),
            Prover::Groth16(p) => (p.r1cs.num_constraints(), p.r1cs.num_witnesses()),
        }
    }

    /// Returns the WHIR scheme for backends that use it (Noir, Mavros).
    /// Returns `None` for Groth16, which doesn't use WHIR.
    pub fn whir_for_witness(&self) -> Option<&provekit_common::WhirR1CSScheme> {
        match self {
            Prover::Noir(p) => Some(&p.whir_for_witness),
            Prover::Mavros(p) => Some(&p.whir_for_witness),
            Prover::Groth16(_) => None,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl MaybeHashAware for Prover {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        match self {
            Prover::Noir(p) => Some(p.hash_config),
            Prover::Mavros(p) => Some(p.hash_config),
            Prover::Groth16(_) => None,
        }
    }
}
