//! mmap-backed Groth16 proving key.
//!
//! Mirrors rapidsnark's zkey loading approach (see
//! `rapidsnark/src/fileloader.cpp` + `binfile_utils.cpp` + `zkey_utils.cpp`):
//! the file is mmap'd once, sections are indexed from a small in-file table,
//! and big curve-point arrays are exposed as `&[G1Affine]` / `&[G2Affine]`
//! slices that point directly into the mmap'd region. No per-point
//! deserialization, no copy.
//!
//! Coexists with the existing zstd-compressed `.pkp` path
//! (`provekit_prover::pkp_io`); the on-disk discriminator is the 4-byte
//! sentinel that follows the 21-byte common header — `MMAP_SENTINEL` here vs.
//! zstd/xz magic in the legacy path.
//!
//! ## On-disk layout (after the 21-byte common header)
//!
//! ```text
//! [ MMAP_SENTINEL                    4 bytes   ]
//! [ metadata_len  (u64 LE)           8 bytes   ]
//! [ postcard-encoded Prover          metadata_len bytes  (PK = zero-byte placeholder) ]
//! [ pad to 8-byte align                       ]
//! [ section_count (u32 LE)           4 bytes   ]
//! [ section table (id u32, off u64, len u64) × section_count ]
//! [ pad to MMAP_ALIGN                         ]
//! [ section bodies (raw arkworks in-memory layout for big arrays) ]
//! ```
//!
//! Section IDs are listed in [`SectionId`].
//!
//! ## Why this layout assumes raw Montgomery in-memory bytes
//!
//! Arkworks `G1Affine` / `G2Affine` for BN254 are repr-Rust structs containing
//! `Fp<MontBackend, 4>` field elements. The bytes stored on disk are produced
//! by `slice::from_raw_parts(slice.as_ptr() as *const u8, ...)` — i.e. the
//! exact in-memory representation including Montgomery form. On read, the
//! mmap'd bytes are reinterpreted via [`std::slice::from_raw_parts`] back into
//! `&[G1Affine]`. This matches rapidsnark's `(G1PointAffine *)ptr` cast.
//!
//! The cost is layout coupling: a future arkworks version that changes the
//! `Affine` struct layout (or its `Fp` representation) silently breaks the
//! file format. The format is therefore versioned via the common header's
//! `PROVER_VERSION`; bump the version when the layout assumption changes.

#![cfg(not(target_arch = "wasm32"))]

use {
    crate::pedersen,
    anyhow::{bail, ensure, Context, Result},
    ark_bn254::{Fr, G1Affine, G2Affine},
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    memmap2::Mmap,
    provekit_common::{InternedFieldElement, Interner, SparseMatrix, R1CS},
    std::{
        fs::{File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        path::Path,
    },
    tracing::info_span,
};

/// 4-byte sentinel that distinguishes a mmap-format `.pkp` from a
/// zstd/xz-compressed one. Placed immediately after the 21-byte common
/// header.
pub const MMAP_SENTINEL: [u8; 4] = *b"MMAP";

/// Required alignment for the start of every section body. Picked to match
/// `align_of::<G1Affine>()` (which is `align_of::<u64>() == 8` on every
/// supported target). Section bodies for `bool` arrays only need 1-byte
/// alignment, but we pad them to `MMAP_ALIGN` too for consistency.
pub const MMAP_ALIGN: usize = 8;

/// Section IDs in the mmap-format `.pkp` file.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SectionId {
    G1A                 = 1,
    G1B                 = 2,
    G1Z                 = 3,
    G1K                 = 4,
    G2B                 = 5,
    InfinityA           = 6,
    InfinityB           = 7,
    /// Small fixed-size data: domain_size, domain_gen, g1_alpha, g1_beta,
    /// g1_delta, g2_beta, g2_delta, nb_infinity_a, nb_infinity_b. Stored
    /// arkworks-uncompressed. As of PROVER_VERSION (1, 4) pedersen
    /// commitment keys are no longer appended here — they live in
    /// dedicated raw sections (`PedersenIndex`, `PedersenBases`,
    /// `PedersenBasesExpSigma`) so loading them does not require
    /// per-point arkworks deserialization.
    Scalars             = 8,
    /// Per-commitment lengths: `u64 num_commitments` followed by
    /// `num_commitments × (u64 basis_len, u64 sigma_len)`. Lets the
    /// reader split the two raw G1Affine sections below into per-commit
    /// slices.
    PedersenIndex       = 9,
    /// Raw `G1Affine` bytes for `pedersen::ProvingKey::basis`, concatenated
    /// across all commitments. Same in-memory Montgomery layout as the
    /// `G1A` / `G1B` sections — copied (not borrowed) into owned
    /// `Vec<G1Affine>` on load, no arkworks per-point deserialize.
    PedersenBases       = 10,
    /// Raw `G1Affine` bytes for `pedersen::ProvingKey::basis_exp_sigma`,
    /// concatenated across all commitments. Same layout as
    /// `PedersenBases`.
    PedersenBasesExpSigma = 11,
    /// R1CS scalars: a small fixed-shape header with `num_public_inputs`,
    /// `num_virtual`, and per-matrix `num_rows` / `num_cols` for A / B /
    /// C. Stored as raw `u64` bytes (8 fields × 8 bytes = 64 bytes
    /// total).
    R1CSScalars         = 12,
    /// R1CS interner: deduplicated `Vec<FieldElement>` in raw `Fr` bytes
    /// (Montgomery layout, like the G1 sections).
    R1CSInterner        = 13,
    /// `r1cs.a.new_row_indices` raw `u32` bytes.
    R1CSAMatrixRowIndices = 14,
    /// `r1cs.a.col_indices` raw `u32` bytes (absolute column indices —
    /// the mmap format does not delta-encode).
    R1CSAMatrixColIndices = 15,
    /// `r1cs.a.values` raw `usize` (`InternedFieldElement` newtype)
    /// bytes.
    R1CSAMatrixValues   = 16,
    /// `r1cs.b.new_row_indices` raw `u32` bytes.
    R1CSBMatrixRowIndices = 17,
    /// `r1cs.b.col_indices` raw `u32` bytes.
    R1CSBMatrixColIndices = 18,
    /// `r1cs.b.values` raw `usize` bytes.
    R1CSBMatrixValues   = 19,
    /// `r1cs.c.new_row_indices` raw `u32` bytes.
    R1CSCMatrixRowIndices = 20,
    /// `r1cs.c.col_indices` raw `u32` bytes.
    R1CSCMatrixColIndices = 21,
    /// `r1cs.c.values` raw `usize` bytes.
    R1CSCMatrixValues   = 22,
    /// Commitment-info index: `u64 num_commitments` followed by
    /// `num_commitments × (u64 pub_len, u64 priv_len, u64 chal_len)`.
    /// Lets the reader split the three raw `u64` sections below into
    /// per-commitment slices.
    CommitmentInfoIndex = 23,
    /// `Groth16CommitmentInfo::public_committed` raw `u64` bytes,
    /// concatenated across all commitments. (`usize` on 64-bit hosts is
    /// 8 bytes; we always store as `u64` for portability.)
    CommitmentInfoPublicCommitted = 24,
    /// `Groth16CommitmentInfo::private_committed` raw `u64` bytes.
    CommitmentInfoPrivateCommitted = 25,
    /// `Groth16CommitmentInfo::challenge_indices` raw `u64` bytes.
    CommitmentInfoChallengeIndices = 26,
}

impl SectionId {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::G1A),
            2 => Some(Self::G1B),
            3 => Some(Self::G1Z),
            4 => Some(Self::G1K),
            5 => Some(Self::G2B),
            6 => Some(Self::InfinityA),
            7 => Some(Self::InfinityB),
            8 => Some(Self::Scalars),
            9 => Some(Self::PedersenIndex),
            10 => Some(Self::PedersenBases),
            11 => Some(Self::PedersenBasesExpSigma),
            12 => Some(Self::R1CSScalars),
            13 => Some(Self::R1CSInterner),
            14 => Some(Self::R1CSAMatrixRowIndices),
            15 => Some(Self::R1CSAMatrixColIndices),
            16 => Some(Self::R1CSAMatrixValues),
            17 => Some(Self::R1CSBMatrixRowIndices),
            18 => Some(Self::R1CSBMatrixColIndices),
            19 => Some(Self::R1CSBMatrixValues),
            20 => Some(Self::R1CSCMatrixRowIndices),
            21 => Some(Self::R1CSCMatrixColIndices),
            22 => Some(Self::R1CSCMatrixValues),
            23 => Some(Self::CommitmentInfoIndex),
            24 => Some(Self::CommitmentInfoPublicCommitted),
            25 => Some(Self::CommitmentInfoPrivateCommitted),
            26 => Some(Self::CommitmentInfoChallengeIndices),
            _ => None,
        }
    }
}

/// Compile-time assertion that arkworks BN254 `G1Affine` / `G2Affine` align to
/// at most `MMAP_ALIGN`. If a future arkworks version raises alignment, this
/// trips and the file format must be revisited.
const _: () = {
    assert!(std::mem::align_of::<G1Affine>() <= MMAP_ALIGN);
    assert!(std::mem::align_of::<G2Affine>() <= MMAP_ALIGN);
};

/// Mmap-backed proving key: identical fields to [`crate::ProvingKey`] but the
/// large arrays are slices into an mmap'd file rather than owned `Vec`s.
///
/// The `_mmap` field keeps the file mapping alive for the lifetime of the
/// struct; the raw pointer/length pairs index into it. The accessor methods
/// (`g1_a()` etc.) return slices with the struct's lifetime, so the borrow
/// checker prevents callers from outliving the mapping.
///
/// SAFETY: `*_ptr` fields point into `_mmap`'s mapped region. Constructed
/// only via [`MmapProvingKey::load`], which validates section bounds and
/// alignment.
pub struct MmapProvingKey {
    /// Holds the file mapping alive. Never accessed after construction.
    _mmap: Mmap,

    pub domain_size: u64,
    pub domain_gen:  Fr,

    pub g1_alpha: G1Affine,
    pub g1_beta:  G1Affine,
    pub g1_delta: G1Affine,

    g1_a_ptr: *const G1Affine,
    g1_a_len: usize,
    g1_b_ptr: *const G1Affine,
    g1_b_len: usize,
    g1_k_ptr: *const G1Affine,
    g1_k_len: usize,
    g1_z_ptr: *const G1Affine,
    g1_z_len: usize,

    pub g2_beta:  G2Affine,
    pub g2_delta: G2Affine,
    g2_b_ptr:     *const G2Affine,
    g2_b_len:     usize,

    infinity_a_ptr: *const bool,
    infinity_a_len: usize,
    infinity_b_ptr: *const bool,
    infinity_b_len: usize,

    pub nb_infinity_a: u64,
    pub nb_infinity_b: u64,

    /// Wire indices where `A(τ) != 0`, derived once at load from
    /// `infinity_a`. Owned (not borrowed from the mmap) — the file format
    /// doesn't store this; it's a cheap O(n) one-time computation.
    pub non_inf_a: Vec<usize>,
    /// Wire indices where `B(τ) != 0`, derived once at load from
    /// `infinity_b`.
    pub non_inf_b: Vec<usize>,

    /// Raw-pointer descriptors for each Pedersen commitment key. The
    /// pointers index into the same `_mmap` mapping above. Lifetime is
    /// implicit through `&self` — accessors return `&[G1Affine]` slices
    /// bound to `&self`. No memcpy on load, unlike the legacy
    /// `Vec<pedersen::ProvingKey>` field this replaces.
    pub commitment_keys: Vec<MmapPedersenProvingKey>,
}

/// Borrowed Pedersen proving key whose basis arrays point into an mmap'd
/// `.pkp` file. Layout-compatible with [`pedersen::ProvingKey`] (the
/// underlying `G1Affine` bytes are in the same in-memory Montgomery form
/// as the `G1A` / `G1B` sections), but no `Vec<G1Affine>` is ever
/// allocated — the pointers reference file pages directly.
///
/// SAFETY: the pointers are only valid while the parent `MmapProvingKey`
/// (and therefore its `_mmap`) is alive. Construction and use are gated
/// behind that lifetime via the `&self` borrow on the accessors.
pub struct MmapPedersenProvingKey {
    basis_ptr:           *const G1Affine,
    basis_len:           usize,
    basis_exp_sigma_ptr: *const G1Affine,
    basis_exp_sigma_len: usize,
}

// SAFETY: raw pointers into a read-only `Mmap`, same justification as the
// `MmapProvingKey` Send / Sync impls below.
unsafe impl Send for MmapPedersenProvingKey {}
unsafe impl Sync for MmapPedersenProvingKey {}

impl MmapPedersenProvingKey {
    pub fn basis(&self) -> &[G1Affine] {
        // SAFETY: pointer / length validated by `load_pedersen_commitment_keys`
        // (alignment + bounds against the section); mapping outlives `&self`.
        unsafe { std::slice::from_raw_parts(self.basis_ptr, self.basis_len) }
    }

    pub fn basis_exp_sigma(&self) -> &[G1Affine] {
        // SAFETY: see `basis`.
        unsafe { std::slice::from_raw_parts(self.basis_exp_sigma_ptr, self.basis_exp_sigma_len) }
    }

    /// Borrow this mmap-backed key as a `pedersen::ProvingKeyView`, so
    /// callers can run the same `commit` / `prove_knowledge` logic
    /// whether the bases are owned or mmap-backed.
    pub fn view(&self) -> pedersen::ProvingKeyView<'_> {
        pedersen::ProvingKeyView {
            basis:           self.basis(),
            basis_exp_sigma: self.basis_exp_sigma(),
        }
    }
}

// SAFETY: `*_ptr` fields point into a read-only `Mmap`. Mmap pages are
// shareable across threads (the kernel handles paging), and we never mutate
// through the pointers. `Vec<pedersen::ProvingKey>` is already Send + Sync.
unsafe impl Send for MmapProvingKey {}
// SAFETY: same as Send — read-only access through aliasable pointers into a
// shared mapping.
unsafe impl Sync for MmapProvingKey {}

impl std::fmt::Debug for MmapProvingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapProvingKey")
            .field("domain_size", &self.domain_size)
            .field("g1_a_len", &self.g1_a_len)
            .field("g1_b_len", &self.g1_b_len)
            .field("g1_k_len", &self.g1_k_len)
            .field("g1_z_len", &self.g1_z_len)
            .field("g2_b_len", &self.g2_b_len)
            .field("nb_infinity_a", &self.nb_infinity_a)
            .field("nb_infinity_b", &self.nb_infinity_b)
            .field("nb_commitment_keys", &self.commitment_keys.len())
            .finish()
    }
}

impl MmapProvingKey {
    pub fn g1_a(&self) -> &[G1Affine] {
        // SAFETY: pointer/len validated in `load`; mapping outlives `&self`.
        unsafe { std::slice::from_raw_parts(self.g1_a_ptr, self.g1_a_len) }
    }

    pub fn g1_b(&self) -> &[G1Affine] {
        // SAFETY: see `g1_a`.
        unsafe { std::slice::from_raw_parts(self.g1_b_ptr, self.g1_b_len) }
    }

    pub fn g1_k(&self) -> &[G1Affine] {
        // SAFETY: see `g1_a`.
        unsafe { std::slice::from_raw_parts(self.g1_k_ptr, self.g1_k_len) }
    }

    pub fn g1_z(&self) -> &[G1Affine] {
        // SAFETY: see `g1_a`.
        unsafe { std::slice::from_raw_parts(self.g1_z_ptr, self.g1_z_len) }
    }

    pub fn g2_b(&self) -> &[G2Affine] {
        // SAFETY: see `g1_a`.
        unsafe { std::slice::from_raw_parts(self.g2_b_ptr, self.g2_b_len) }
    }

    pub fn infinity_a(&self) -> &[bool] {
        // SAFETY: see `g1_a`. `bool` has alignment 1, len validated.
        unsafe { std::slice::from_raw_parts(self.infinity_a_ptr, self.infinity_a_len) }
    }

    pub fn infinity_b(&self) -> &[bool] {
        // SAFETY: see `infinity_a`.
        unsafe { std::slice::from_raw_parts(self.infinity_b_ptr, self.infinity_b_len) }
    }

    /// Load a proving key from a mmap-format file. The file's 21-byte common
    /// header has already been read and validated by the caller; `data_offset`
    /// is the offset (within the mmap) where the [`MMAP_SENTINEL`] starts.
    ///
    /// The caller is responsible for any postcard metadata that lives in the
    /// same file — this function reads only the section table and section
    /// bodies for the proving key.
    pub fn load(mmap: Mmap, sections_start: usize) -> Result<Self> {
        ensure!(
            sections_start + 4 <= mmap.len(),
            "mmap pkp: section_count out of bounds"
        );
        let section_count =
            u32::from_le_bytes(mmap[sections_start..sections_start + 4].try_into().unwrap());
        let table_start = sections_start + 4;
        let table_entry_bytes = 4 + 8 + 8;
        let table_end = table_start + section_count as usize * table_entry_bytes;
        ensure!(
            table_end <= mmap.len(),
            "mmap pkp: section table out of bounds (table_end={}, file_len={})",
            table_end,
            mmap.len()
        );

        // Parse section table.
        let section_offsets = {
            let _s = info_span!("section_table_parse", section_count).entered();
            let mut section_offsets = std::collections::HashMap::<SectionId, (usize, usize)>::new();
            for i in 0..section_count {
                let entry = table_start + i as usize * table_entry_bytes;
                let id = u32::from_le_bytes(mmap[entry..entry + 4].try_into().unwrap());
                let off =
                    u64::from_le_bytes(mmap[entry + 4..entry + 12].try_into().unwrap()) as usize;
                let len =
                    u64::from_le_bytes(mmap[entry + 12..entry + 20].try_into().unwrap()) as usize;
                ensure!(
                    off + len <= mmap.len(),
                    "mmap pkp: section {} body out of bounds",
                    id
                );
                let Some(sid) = SectionId::from_u32(id) else {
                    bail!("mmap pkp: unknown section id {}", id);
                };
                section_offsets.insert(sid, (off, len));
            }
            section_offsets
        };

        let g1_size = std::mem::size_of::<G1Affine>();
        let g2_size = std::mem::size_of::<G2Affine>();

        let load_g1_section = |sid: SectionId| -> Result<(*const G1Affine, usize)> {
            let (off, len) = *section_offsets
                .get(&sid)
                .ok_or_else(|| anyhow::anyhow!("missing section {:?}", sid))?;
            ensure!(
                off % MMAP_ALIGN == 0,
                "section {:?} body not aligned (off={})",
                sid,
                off
            );
            ensure!(
                len % g1_size == 0,
                "section {:?} body length {} not a multiple of size_of::<G1Affine>()={}",
                sid,
                len,
                g1_size
            );
            let count = len / g1_size;
            let ptr = unsafe { mmap.as_ptr().add(off) } as *const G1Affine;
            Ok((ptr, count))
        };

        let load_g2_section = |sid: SectionId| -> Result<(*const G2Affine, usize)> {
            let (off, len) = *section_offsets
                .get(&sid)
                .ok_or_else(|| anyhow::anyhow!("missing section {:?}", sid))?;
            ensure!(
                off % MMAP_ALIGN == 0,
                "section {:?} body not aligned (off={})",
                sid,
                off
            );
            ensure!(
                len % g2_size == 0,
                "section {:?} body length {} not a multiple of size_of::<G2Affine>()={}",
                sid,
                len,
                g2_size
            );
            let count = len / g2_size;
            let ptr = unsafe { mmap.as_ptr().add(off) } as *const G2Affine;
            Ok((ptr, count))
        };

        let load_bool_section = |sid: SectionId| -> Result<(*const bool, usize)> {
            let (off, len) = *section_offsets
                .get(&sid)
                .ok_or_else(|| anyhow::anyhow!("missing section {:?}", sid))?;
            ensure!(
                off.checked_add(len).map_or(false, |end| end <= mmap.len()),
                "section {:?} body out of bounds (off={}, len={})",
                sid,
                off,
                len
            );
            // SAFETY: reinterpreting bytes as `&[bool]` is UB unless every byte
            // is 0 or 1. The mmap is attacker-controllable on iOS/Android, so
            // validate the bool validity invariant before exposing the slice.
            let bytes = &mmap[off..off + len];
            ensure!(
                bytes.iter().all(|&b| b <= 1),
                "section {:?} contains invalid bool byte (not 0 or 1)",
                sid
            );
            let ptr = bytes.as_ptr() as *const bool;
            Ok((ptr, len))
        };

        let (
            g1_a_ptr,
            g1_a_len,
            g1_b_ptr,
            g1_b_len,
            g1_z_ptr,
            g1_z_len,
            g1_k_ptr,
            g1_k_len,
            g2_b_ptr,
            g2_b_len,
            infinity_a_ptr,
            infinity_a_len,
            infinity_b_ptr,
            infinity_b_len,
        ) = {
            let _s = info_span!("bulk_section_pointers").entered();
            let (g1_a_ptr, g1_a_len) = load_g1_section(SectionId::G1A)?;
            let (g1_b_ptr, g1_b_len) = load_g1_section(SectionId::G1B)?;
            let (g1_z_ptr, g1_z_len) = load_g1_section(SectionId::G1Z)?;
            let (g1_k_ptr, g1_k_len) = load_g1_section(SectionId::G1K)?;
            let (g2_b_ptr, g2_b_len) = load_g2_section(SectionId::G2B)?;
            let (infinity_a_ptr, infinity_a_len) = load_bool_section(SectionId::InfinityA)?;
            let (infinity_b_ptr, infinity_b_len) = load_bool_section(SectionId::InfinityB)?;
            (
                g1_a_ptr,
                g1_a_len,
                g1_b_ptr,
                g1_b_len,
                g1_z_ptr,
                g1_z_len,
                g1_k_ptr,
                g1_k_len,
                g2_b_ptr,
                g2_b_len,
                infinity_a_ptr,
                infinity_a_len,
                infinity_b_ptr,
                infinity_b_len,
            )
        };

        // Scalars: arkworks-uncompressed.
        let (sp_off, sp_len) = *section_offsets
            .get(&SectionId::Scalars)
            .ok_or_else(|| anyhow::anyhow!("missing scalars section"))?;
        let mut sp = &mmap[sp_off..sp_off + sp_len];

        let (
            domain_size,
            domain_gen,
            g1_alpha,
            g1_beta,
            g1_delta,
            g2_beta,
            g2_delta,
            nb_infinity_a,
            nb_infinity_b,
        ) = {
            let _s = info_span!("scalars_deserialize", sp_len).entered();
            let domain_size =
                u64::deserialize_uncompressed_unchecked(&mut sp).context("read domain_size")?;
            let domain_gen =
                Fr::deserialize_uncompressed_unchecked(&mut sp).context("read domain_gen")?;
            let g1_alpha =
                G1Affine::deserialize_uncompressed_unchecked(&mut sp).context("read g1_alpha")?;
            let g1_beta =
                G1Affine::deserialize_uncompressed_unchecked(&mut sp).context("read g1_beta")?;
            let g1_delta =
                G1Affine::deserialize_uncompressed_unchecked(&mut sp).context("read g1_delta")?;
            let g2_beta =
                G2Affine::deserialize_uncompressed_unchecked(&mut sp).context("read g2_beta")?;
            let g2_delta =
                G2Affine::deserialize_uncompressed_unchecked(&mut sp).context("read g2_delta")?;
            let nb_infinity_a =
                u64::deserialize_uncompressed_unchecked(&mut sp).context("read nb_infinity_a")?;
            let nb_infinity_b =
                u64::deserialize_uncompressed_unchecked(&mut sp).context("read nb_infinity_b")?;
            (
                domain_size,
                domain_gen,
                g1_alpha,
                g1_beta,
                g1_delta,
                g2_beta,
                g2_delta,
                nb_infinity_a,
                nb_infinity_b,
            )
        };

        // Pedersen commitment keys: raw G1Affine bytes in three sections.
        // Layout-compatible with the bulk G1 sections (same in-memory
        // Montgomery form), but built into owned `Vec<G1Affine>` here so
        // the existing `pedersen::ProvingKey` API stays intact. The copy
        // is one memcpy per basis/sigma slice — no per-point arkworks
        // deserialization, no Montgomery rebuild.
        let commitment_keys = {
            let _s = info_span!("pedersen_commitment_keys_load").entered();
            load_pedersen_commitment_keys(&mmap, &section_offsets)?
        };

        // Derive non-infinity index lists from the mmap'd `infinity_a/b`
        // bytes. One-time O(n) walk at load — amortized across every
        // subsequent prove call.
        // SAFETY: pointers / lengths were validated by `load_bool_section`
        // above, and the mapping outlives this scope.
        let infinity_a_slice: &[bool] =
            unsafe { std::slice::from_raw_parts(infinity_a_ptr, infinity_a_len) };
        let infinity_b_slice: &[bool] =
            unsafe { std::slice::from_raw_parts(infinity_b_ptr, infinity_b_len) };
        let non_inf_a: Vec<usize> = infinity_a_slice
            .iter()
            .enumerate()
            .filter_map(|(i, &x)| if !x { Some(i) } else { None })
            .collect();
        let non_inf_b: Vec<usize> = infinity_b_slice
            .iter()
            .enumerate()
            .filter_map(|(i, &x)| if !x { Some(i) } else { None })
            .collect();

        Ok(MmapProvingKey {
            _mmap: mmap,
            domain_size,
            domain_gen,
            g1_alpha,
            g1_beta,
            g1_delta,
            g1_a_ptr,
            g1_a_len,
            g1_b_ptr,
            g1_b_len,
            g1_k_ptr,
            g1_k_len,
            g1_z_ptr,
            g1_z_len,
            g2_beta,
            g2_delta,
            g2_b_ptr,
            g2_b_len,
            infinity_a_ptr,
            infinity_a_len,
            infinity_b_ptr,
            infinity_b_len,
            nb_infinity_a,
            nb_infinity_b,
            non_inf_a,
            non_inf_b,
            commitment_keys,
        })
    }
}

/// Read the three Pedersen sections and build
/// `Vec<MmapPedersenProvingKey>` with raw pointers into the mmap. Pure
/// zero-copy — no `Vec<G1Affine>` is allocated, no per-point arkworks
/// deserialization, no memcpy of the basis bytes. Allocation cost is one
/// outer `Vec<MmapPedersenProvingKey>` of `num_commitments` × 32-byte
/// descriptors (a few hundred bytes for typical circuits).
///
/// If there are no commitment keys (circuit without BSB22 commitments)
/// the index section still exists but encodes zero commitments, and
/// the two byte sections are empty.
fn load_pedersen_commitment_keys(
    mmap: &Mmap,
    section_offsets: &std::collections::HashMap<SectionId, (usize, usize)>,
) -> Result<Vec<MmapPedersenProvingKey>> {
    let g1_size = std::mem::size_of::<G1Affine>();

    let (idx_off, idx_len) = *section_offsets
        .get(&SectionId::PedersenIndex)
        .ok_or_else(|| anyhow::anyhow!("missing pedersen index section"))?;
    let (bases_off, bases_len) = *section_offsets
        .get(&SectionId::PedersenBases)
        .ok_or_else(|| anyhow::anyhow!("missing pedersen bases section"))?;
    let (sigma_off, sigma_len) = *section_offsets
        .get(&SectionId::PedersenBasesExpSigma)
        .ok_or_else(|| anyhow::anyhow!("missing pedersen basis_exp_sigma section"))?;

    ensure!(
        bases_off % MMAP_ALIGN == 0,
        "PedersenBases body not aligned (off={})",
        bases_off
    );
    ensure!(
        sigma_off % MMAP_ALIGN == 0,
        "PedersenBasesExpSigma body not aligned (off={})",
        sigma_off
    );
    ensure!(
        bases_len % g1_size == 0,
        "PedersenBases body length {} not a multiple of size_of::<G1Affine>()={}",
        bases_len,
        g1_size
    );
    ensure!(
        sigma_len % g1_size == 0,
        "PedersenBasesExpSigma body length {} not a multiple of size_of::<G1Affine>()={}",
        sigma_len,
        g1_size
    );

    // Parse the index: u64 num_commitments followed by num × (u64
    // basis_len, u64 sigma_len). Validate that the sum of per-commit
    // lengths exactly matches the byte sections.
    ensure!(idx_len >= 8, "pedersen index too short for num_commitments");
    let num_commitments =
        u64::from_le_bytes(mmap[idx_off..idx_off + 8].try_into().unwrap()) as usize;
    let expected_idx_len = 8 + num_commitments * 16;
    ensure!(
        idx_len == expected_idx_len,
        "pedersen index length mismatch (got {}, expected {})",
        idx_len,
        expected_idx_len
    );

    let mut commitment_keys = Vec::with_capacity(num_commitments);
    let mut basis_cursor = bases_off;
    let mut sigma_cursor = sigma_off;
    let bases_end = bases_off + bases_len;
    let sigma_end = sigma_off + sigma_len;

    for i in 0..num_commitments {
        let entry = idx_off + 8 + i * 16;
        let basis_count = u64::from_le_bytes(mmap[entry..entry + 8].try_into().unwrap()) as usize;
        let sigma_count =
            u64::from_le_bytes(mmap[entry + 8..entry + 16].try_into().unwrap()) as usize;

        let basis_bytes = basis_count * g1_size;
        let sigma_bytes = sigma_count * g1_size;
        ensure!(
            basis_cursor + basis_bytes <= bases_end,
            "pedersen basis #{} runs past PedersenBases section",
            i
        );
        ensure!(
            sigma_cursor + sigma_bytes <= sigma_end,
            "pedersen basis_exp_sigma #{} runs past PedersenBasesExpSigma section",
            i
        );

        // SAFETY: section offsets validated MMAP_ALIGN-aligned above,
        // lengths are multiples of size_of::<G1Affine>(), pointers stay
        // within the section bounds we just checked. The raw bytes are
        // in the same in-memory Montgomery layout written by
        // `write_pk_sections` (see the `[G1Affine] as &[u8]` cast there
        // — the inverse cast here is layout-compatible). The pointers
        // are stored alongside the mmap they index into in
        // `MmapProvingKey`; accessors are bound to `&self` on that
        // struct so the pointers can never outlive the mapping.
        let basis_ptr = unsafe { mmap.as_ptr().add(basis_cursor) as *const G1Affine };
        let basis_exp_sigma_ptr = unsafe { mmap.as_ptr().add(sigma_cursor) as *const G1Affine };
        commitment_keys.push(MmapPedersenProvingKey {
            basis_ptr,
            basis_len: basis_count,
            basis_exp_sigma_ptr,
            basis_exp_sigma_len: sigma_count,
        });

        basis_cursor += basis_bytes;
        sigma_cursor += sigma_bytes;
    }

    ensure!(
        basis_cursor == bases_end,
        "PedersenBases section has {} trailing bytes after all commitments",
        bases_end - basis_cursor
    );
    ensure!(
        sigma_cursor == sigma_end,
        "PedersenBasesExpSigma section has {} trailing bytes after all commitments",
        sigma_end - sigma_cursor
    );

    Ok(commitment_keys)
}

/// Write the curve-point sections of a [`crate::ProvingKey`] in mmap-friendly
/// raw layout, plus a small arkworks-encoded scalars+pedersen section.
///
/// Writes at the current file position. The 21-byte common header,
/// [`MMAP_SENTINEL`], and the postcard-encoded prover metadata are written by
/// the caller (lives in `provekit_prover::pkp_io`); this function appends the
/// section table and section bodies.
///
/// Returns the number of bytes written.
pub fn write_pk_sections(pk: &crate::ProvingKey, file: &mut File) -> Result<u64> {
    // Build the scalars blob first so we know its length. As of
    // PROVER_VERSION (1, 4) pedersen `commitment_keys` are no longer
    // included here — they live in dedicated raw G1Affine sections
    // (PedersenIndex / PedersenBases / PedersenBasesExpSigma) and are
    // memcpy'd, not arkworks-deserialized, on load.
    let mut sp_bytes: Vec<u8> = Vec::new();
    pk.domain_size
        .serialize_uncompressed(&mut sp_bytes)
        .context("write domain_size")?;
    pk.domain_gen
        .serialize_uncompressed(&mut sp_bytes)
        .context("write domain_gen")?;
    pk.g1_alpha
        .serialize_uncompressed(&mut sp_bytes)
        .context("write g1_alpha")?;
    pk.g1_beta
        .serialize_uncompressed(&mut sp_bytes)
        .context("write g1_beta")?;
    pk.g1_delta
        .serialize_uncompressed(&mut sp_bytes)
        .context("write g1_delta")?;
    pk.g2_beta
        .serialize_uncompressed(&mut sp_bytes)
        .context("write g2_beta")?;
    pk.g2_delta
        .serialize_uncompressed(&mut sp_bytes)
        .context("write g2_delta")?;
    pk.nb_infinity_a
        .serialize_uncompressed(&mut sp_bytes)
        .context("write nb_infinity_a")?;
    pk.nb_infinity_b
        .serialize_uncompressed(&mut sp_bytes)
        .context("write nb_infinity_b")?;

    // Build the pedersen index: u64 num_commitments, then per-commit
    // (u64 basis_len, u64 sigma_len). The two body sections store the
    // raw G1Affine bytes concatenated in the same order.
    let mut pedersen_index: Vec<u8> = Vec::new();
    pedersen_index.extend_from_slice(&(pk.commitment_keys.len() as u64).to_le_bytes());
    let mut total_basis_count: u64 = 0;
    let mut total_sigma_count: u64 = 0;
    for ck in &pk.commitment_keys {
        pedersen_index.extend_from_slice(&(ck.basis.len() as u64).to_le_bytes());
        pedersen_index.extend_from_slice(&(ck.basis_exp_sigma.len() as u64).to_le_bytes());
        total_basis_count += ck.basis.len() as u64;
        total_sigma_count += ck.basis_exp_sigma.len() as u64;
    }

    // Section bodies (in the order they'll be written).
    let g1_size = std::mem::size_of::<G1Affine>();
    let g2_size = std::mem::size_of::<G2Affine>();

    // (id, body_byte_len)
    let sections: [(SectionId, u64); 11] = [
        (SectionId::G1A, (pk.g1_a.len() * g1_size) as u64),
        (SectionId::G1B, (pk.g1_b.len() * g1_size) as u64),
        (SectionId::G1Z, (pk.g1_z.len() * g1_size) as u64),
        (SectionId::G1K, (pk.g1_k.len() * g1_size) as u64),
        (SectionId::G2B, (pk.g2_b.len() * g2_size) as u64),
        (SectionId::InfinityA, pk.infinity_a.len() as u64),
        (SectionId::InfinityB, pk.infinity_b.len() as u64),
        (SectionId::Scalars, sp_bytes.len() as u64),
        (SectionId::PedersenIndex, pedersen_index.len() as u64),
        (SectionId::PedersenBases, total_basis_count * g1_size as u64),
        (
            SectionId::PedersenBasesExpSigma,
            total_sigma_count * g1_size as u64,
        ),
    ];

    // Compute byte offsets for each section body, padding each to MMAP_ALIGN.
    // Offsets are absolute in the file. We need to know:
    //   table_start = current file pos + 4 (section_count u32)
    //   table_end   = table_start + section_count * (4+8+8)
    //   body_start  = round_up(table_end, MMAP_ALIGN)
    let table_start = file.stream_position()? + 4;
    let table_end = table_start + sections.len() as u64 * 20;
    let mut cur_off = round_up(table_end, MMAP_ALIGN as u64);

    let mut section_offsets: Vec<(SectionId, u64, u64)> = Vec::with_capacity(sections.len());
    for &(id, len) in &sections {
        section_offsets.push((id, cur_off, len));
        cur_off = round_up(cur_off + len, MMAP_ALIGN as u64);
    }
    let total_end = cur_off;

    // Write section count.
    file.write_all(&(sections.len() as u32).to_le_bytes())?;
    // Write section table.
    for &(id, off, len) in &section_offsets {
        file.write_all(&(id as u32).to_le_bytes())?;
        file.write_all(&off.to_le_bytes())?;
        file.write_all(&len.to_le_bytes())?;
    }
    // Pad to body_start.
    let body_start = section_offsets[0].1;
    pad_to(file, body_start)?;

    // Write section bodies, each followed by alignment padding for the next.
    let g1_a_bytes = unsafe {
        std::slice::from_raw_parts(pk.g1_a.as_ptr() as *const u8, pk.g1_a.len() * g1_size)
    };
    write_section_body(file, g1_a_bytes, section_offsets[1].1)?;

    let g1_b_bytes = unsafe {
        std::slice::from_raw_parts(pk.g1_b.as_ptr() as *const u8, pk.g1_b.len() * g1_size)
    };
    write_section_body(file, g1_b_bytes, section_offsets[2].1)?;

    let g1_z_bytes = unsafe {
        std::slice::from_raw_parts(pk.g1_z.as_ptr() as *const u8, pk.g1_z.len() * g1_size)
    };
    write_section_body(file, g1_z_bytes, section_offsets[3].1)?;

    let g1_k_bytes = unsafe {
        std::slice::from_raw_parts(pk.g1_k.as_ptr() as *const u8, pk.g1_k.len() * g1_size)
    };
    write_section_body(file, g1_k_bytes, section_offsets[4].1)?;

    let g2_b_bytes = unsafe {
        std::slice::from_raw_parts(pk.g2_b.as_ptr() as *const u8, pk.g2_b.len() * g2_size)
    };
    write_section_body(file, g2_b_bytes, section_offsets[5].1)?;

    let infinity_a_bytes = unsafe {
        std::slice::from_raw_parts(pk.infinity_a.as_ptr() as *const u8, pk.infinity_a.len())
    };
    write_section_body(file, infinity_a_bytes, section_offsets[6].1)?;

    let infinity_b_bytes = unsafe {
        std::slice::from_raw_parts(pk.infinity_b.as_ptr() as *const u8, pk.infinity_b.len())
    };
    write_section_body(file, infinity_b_bytes, section_offsets[7].1)?;

    // Scalars (small, arkworks-encoded).
    write_section_body(file, &sp_bytes, section_offsets[8].1)?;

    // Pedersen index (small, hand-rolled).
    write_section_body(file, &pedersen_index, section_offsets[9].1)?;

    // Pedersen bases: raw G1Affine bytes concatenated. Mirrors the layout
    // for the G1A/G1B/G1Z/G1K sections so the reader can recover the
    // bases by memcpy instead of arkworks per-point deserialize.
    for ck in &pk.commitment_keys {
        let bytes = unsafe {
            std::slice::from_raw_parts(ck.basis.as_ptr() as *const u8, ck.basis.len() * g1_size)
        };
        file.write_all(bytes)?;
    }
    pad_to(file, section_offsets[10].1)?;

    // Pedersen basis_exp_sigma: raw G1Affine bytes concatenated.
    for ck in &pk.commitment_keys {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                ck.basis_exp_sigma.as_ptr() as *const u8,
                ck.basis_exp_sigma.len() * g1_size,
            )
        };
        file.write_all(bytes)?;
    }
    pad_to(file, total_end)?;

    Ok(total_end - (table_start - 4))
}

fn round_up(v: u64, align: u64) -> u64 {
    (v + align - 1) / align * align
}

fn pad_to(file: &mut File, target: u64) -> Result<()> {
    let cur = file.stream_position()?;
    if cur < target {
        let pad = vec![0u8; (target - cur) as usize];
        file.write_all(&pad)?;
    } else if cur > target {
        bail!("pad_to: current position {} is past target {}", cur, target);
    }
    Ok(())
}

fn write_section_body(file: &mut File, body: &[u8], next_section_off: u64) -> Result<()> {
    file.write_all(body)?;
    pad_to(file, next_section_off)
}

// ---------------------------------------------------------------------------
// R1CS chunk: raw-byte layout for the R1CS struct, appended after the PK
// section table so the mmap reader can memcpy it back without going through
// postcard (~70 ms → ~3-5 ms on the noir_sha256 benchmark).
// ---------------------------------------------------------------------------

/// Per-commitment lengths used by the writer to size the
/// commitment-info chunk, and returned by the reader after parsing the
/// chunk. Each triple is `(public_committed, private_committed,
/// challenge_indices)` as `Vec<u64>` (the prover crate converts to and
/// from `Vec<usize>` at the boundary).
pub type CommitmentInfoTriple = (Vec<u64>, Vec<u64>, Vec<u64>);

const R1CS_CHUNK_MAGIC: [u8; 4] = *b"R1CS";
const CI_CHUNK_MAGIC: [u8; 4] = *b"CINF";

/// Write an R1CS to disk in mmap-friendly raw byte layout. Caller passes
/// the file at the position where the chunk should start; chunk is
/// 8-byte aligned. Returns the absolute file position immediately
/// after the chunk (which is where the next chunk, e.g. commitment_info,
/// should be written).
///
/// Layout:
/// ```text
/// [ "R1CS" magic (4) ]
/// [ pad (4) ]
/// [ u64 num_public_inputs ]
/// [ u64 num_virtual ]
/// [ u64 a_num_rows ]   [ u64 a_num_cols ]
/// [ u64 b_num_rows ]   [ u64 b_num_cols ]
/// [ u64 c_num_rows ]   [ u64 c_num_cols ]
/// [ u64 interner_len ]
/// [ raw Fr bytes × interner_len ]      [ pad to 8 ]
/// for each matrix (a, b, c):
///     [ u64 new_row_indices_len ]      [ raw u32 bytes ]   [ pad to 8 ]
///     [ u64 col_indices_len ]          [ raw u32 bytes ]   [ pad to 8 ]
///     [ u64 values_len ]               [ raw usize bytes ] [ pad to 8 ]
/// ```
pub fn write_r1cs_chunk(r1cs: &R1CS, file: &mut File) -> Result<u64> {
    // Align start of chunk to 8 bytes so the raw arrays inside can be
    // slice-cast.
    let chunk_start = round_up(file.stream_position()?, MMAP_ALIGN as u64);
    pad_to(file, chunk_start)?;

    file.write_all(&R1CS_CHUNK_MAGIC)?;
    file.write_all(&[0u8; 4])?; // pad to 8-byte alignment for the u64s
    file.write_all(&(r1cs.num_public_inputs as u64).to_le_bytes())?;
    file.write_all(&(r1cs.num_virtual as u64).to_le_bytes())?;
    file.write_all(&(r1cs.a.num_rows as u64).to_le_bytes())?;
    file.write_all(&(r1cs.a.num_cols as u64).to_le_bytes())?;
    file.write_all(&(r1cs.b.num_rows as u64).to_le_bytes())?;
    file.write_all(&(r1cs.b.num_cols as u64).to_le_bytes())?;
    file.write_all(&(r1cs.c.num_rows as u64).to_le_bytes())?;
    file.write_all(&(r1cs.c.num_cols as u64).to_le_bytes())?;

    // Interner values
    let interner_values = r1cs.interner.values_raw();
    file.write_all(&(interner_values.len() as u64).to_le_bytes())?;
    let interner_bytes = unsafe {
        std::slice::from_raw_parts(
            interner_values.as_ptr() as *const u8,
            interner_values.len() * std::mem::size_of::<Fr>(),
        )
    };
    file.write_all(interner_bytes)?;
    {
        let p = file.stream_position()?;
        pad_to(file, round_up(p, MMAP_ALIGN as u64))?;
    }

    for matrix in [&r1cs.a, &r1cs.b, &r1cs.c] {
        write_sparse_matrix_arrays(matrix, file)?;
    }

    Ok(file.stream_position()?)
}

fn write_sparse_matrix_arrays(matrix: &SparseMatrix, file: &mut File) -> Result<()> {
    let row_indices = matrix.new_row_indices_raw();
    file.write_all(&(row_indices.len() as u64).to_le_bytes())?;
    let row_bytes = unsafe {
        std::slice::from_raw_parts(row_indices.as_ptr() as *const u8, row_indices.len() * 4)
    };
    file.write_all(row_bytes)?;
    {
        let p = file.stream_position()?;
        pad_to(file, round_up(p, MMAP_ALIGN as u64))?;
    }

    let col_indices = matrix.col_indices_raw();
    file.write_all(&(col_indices.len() as u64).to_le_bytes())?;
    let col_bytes = unsafe {
        std::slice::from_raw_parts(col_indices.as_ptr() as *const u8, col_indices.len() * 4)
    };
    file.write_all(col_bytes)?;
    {
        let p = file.stream_position()?;
        pad_to(file, round_up(p, MMAP_ALIGN as u64))?;
    }

    let values = matrix.values_raw();
    file.write_all(&(values.len() as u64).to_le_bytes())?;
    let values_bytes = unsafe {
        std::slice::from_raw_parts(
            values.as_ptr() as *const u8,
            values.len() * std::mem::size_of::<InternedFieldElement>(),
        )
    };
    file.write_all(values_bytes)?;
    {
        let p = file.stream_position()?;
        pad_to(file, round_up(p, MMAP_ALIGN as u64))?;
    }

    Ok(())
}

/// Parse the PK section table at `sections_start` and return the
/// position where the PK section bodies end (max of `offset + len` over
/// all sections, rounded up to `MMAP_ALIGN`). The R1CS chunk starts at
/// this position. Does not consume the mmap.
pub fn pk_sections_end_offset(mmap: &[u8], sections_start: usize) -> Result<usize> {
    ensure!(
        sections_start + 4 <= mmap.len(),
        "section_count out of bounds"
    );
    let section_count =
        u32::from_le_bytes(mmap[sections_start..sections_start + 4].try_into().unwrap());
    let table_start = sections_start + 4;
    let table_entry_bytes = 4 + 8 + 8;
    let table_end = table_start + section_count as usize * table_entry_bytes;
    ensure!(table_end <= mmap.len(), "pk section table out of bounds");

    let mut max_end: usize = round_up(table_end as u64, MMAP_ALIGN as u64) as usize;
    for i in 0..section_count {
        let entry = table_start + i as usize * table_entry_bytes;
        let off = u64::from_le_bytes(mmap[entry + 4..entry + 12].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(mmap[entry + 12..entry + 20].try_into().unwrap()) as usize;
        let end_rounded = round_up((off + len) as u64, MMAP_ALIGN as u64) as usize;
        if end_rounded > max_end {
            max_end = end_rounded;
        }
    }
    Ok(max_end)
}

/// Read an R1CS chunk back from mmap bytes via memcpy. `bytes` should be
/// the mmap slice starting at the chunk's first byte; the chunk consumes
/// however many bytes its layout requires. Returns the parsed R1CS plus
/// the number of bytes consumed (so the caller can advance to the next
/// chunk).
pub fn read_r1cs_chunk(bytes: &[u8]) -> Result<(R1CS, usize)> {
    ensure!(bytes.len() >= 8, "r1cs chunk too short for magic");
    ensure!(bytes[..4] == R1CS_CHUNK_MAGIC, "r1cs chunk magic mismatch");
    let mut pos = 8usize;
    let read_u64 = |bytes: &[u8], pos: &mut usize| -> Result<u64> {
        ensure!(*pos + 8 <= bytes.len(), "r1cs chunk: short read for u64");
        let v = u64::from_le_bytes(bytes[*pos..*pos + 8].try_into().unwrap());
        *pos += 8;
        Ok(v)
    };

    let num_public_inputs = read_u64(bytes, &mut pos)? as usize;
    let num_virtual = read_u64(bytes, &mut pos)? as usize;
    let a_num_rows = read_u64(bytes, &mut pos)? as usize;
    let a_num_cols = read_u64(bytes, &mut pos)? as usize;
    let b_num_rows = read_u64(bytes, &mut pos)? as usize;
    let b_num_cols = read_u64(bytes, &mut pos)? as usize;
    let c_num_rows = read_u64(bytes, &mut pos)? as usize;
    let c_num_cols = read_u64(bytes, &mut pos)? as usize;

    // Interner
    let interner_len = read_u64(bytes, &mut pos)? as usize;
    let fr_size = std::mem::size_of::<Fr>();
    let interner_bytes_len = interner_len * fr_size;
    ensure!(
        pos + interner_bytes_len <= bytes.len(),
        "r1cs chunk: short read for interner"
    );
    // SAFETY: source bytes are in the same in-memory Montgomery layout
    // written by `write_r1cs_chunk` (Fr-as-raw-bytes cast). Source is
    // 8-byte aligned because `write_r1cs_chunk` pads after each blob.
    let interner_slice: &[Fr] =
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().add(pos) as *const Fr, interner_len) };
    let interner = Interner::from_values(interner_slice.to_vec());
    pos += interner_bytes_len;
    pos = round_up(pos as u64, MMAP_ALIGN as u64) as usize;

    let a = read_sparse_matrix_arrays(bytes, &mut pos, a_num_rows, a_num_cols)?;
    let b = read_sparse_matrix_arrays(bytes, &mut pos, b_num_rows, b_num_cols)?;
    let c = read_sparse_matrix_arrays(bytes, &mut pos, c_num_rows, c_num_cols)?;

    let r1cs = R1CS {
        num_public_inputs,
        interner,
        a,
        b,
        c,
        num_virtual,
    };
    Ok((r1cs, pos))
}

fn read_sparse_matrix_arrays(
    bytes: &[u8],
    pos: &mut usize,
    num_rows: usize,
    num_cols: usize,
) -> Result<SparseMatrix> {
    let read_u64 = |bytes: &[u8], pos: &mut usize| -> Result<u64> {
        ensure!(*pos + 8 <= bytes.len(), "r1cs chunk: short read for u64");
        let v = u64::from_le_bytes(bytes[*pos..*pos + 8].try_into().unwrap());
        *pos += 8;
        Ok(v)
    };

    let row_len = read_u64(bytes, pos)? as usize;
    ensure!(*pos + row_len * 4 <= bytes.len(), "r1cs chunk: short row");
    // SAFETY: writer cast u32 array to bytes; reader does the inverse.
    // Source is 8-byte aligned because `write_r1cs_chunk` pads after
    // each blob and `u32` only needs 4-byte alignment.
    let row_slice: &[u32] =
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().add(*pos) as *const u32, row_len) };
    let new_row_indices = row_slice.to_vec();
    *pos += row_len * 4;
    *pos = round_up(*pos as u64, MMAP_ALIGN as u64) as usize;

    let col_len = read_u64(bytes, pos)? as usize;
    ensure!(*pos + col_len * 4 <= bytes.len(), "r1cs chunk: short cols");
    let col_slice: &[u32] =
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().add(*pos) as *const u32, col_len) };
    let col_indices = col_slice.to_vec();
    *pos += col_len * 4;
    *pos = round_up(*pos as u64, MMAP_ALIGN as u64) as usize;

    let val_len = read_u64(bytes, pos)? as usize;
    let val_size = std::mem::size_of::<InternedFieldElement>();
    ensure!(
        *pos + val_len * val_size <= bytes.len(),
        "r1cs chunk: short values"
    );
    let val_slice: &[InternedFieldElement] = unsafe {
        std::slice::from_raw_parts(
            bytes.as_ptr().add(*pos) as *const InternedFieldElement,
            val_len,
        )
    };
    let values = val_slice.to_vec();
    *pos += val_len * val_size;
    *pos = round_up(*pos as u64, MMAP_ALIGN as u64) as usize;

    Ok(SparseMatrix::from_raw_parts(
        num_rows,
        num_cols,
        new_row_indices,
        col_indices,
        values,
    ))
}

// ---------------------------------------------------------------------------
// commitment_info chunk: raw-byte layout for `Vec<Groth16CommitmentInfo>`,
// stored as triples of `Vec<u64>` (the prover crate converts to/from
// `Vec<usize>` at the boundary).
// ---------------------------------------------------------------------------

/// Write the commitment-info data in raw byte layout. Returns the
/// absolute file position after the chunk.
///
/// Layout:
/// ```text
/// [ "CINF" magic (4) ][ pad (4) ]
/// [ u64 num_commitments ]
/// [ for each commitment: u64 pub_len, u64 priv_len, u64 chal_len ]
/// [ pad to 8 ]
/// [ raw u64 bytes: all pub_committed concatenated ][ pad to 8 ]
/// [ raw u64 bytes: all priv_committed concatenated ][ pad to 8 ]
/// [ raw u64 bytes: all chal_indices concatenated ][ pad to 8 ]
/// ```
pub fn write_commitment_info_chunk(
    triples: &[CommitmentInfoTriple],
    file: &mut File,
) -> Result<u64> {
    let chunk_start = round_up(file.stream_position()?, MMAP_ALIGN as u64);
    pad_to(file, chunk_start)?;

    file.write_all(&CI_CHUNK_MAGIC)?;
    file.write_all(&[0u8; 4])?;
    file.write_all(&(triples.len() as u64).to_le_bytes())?;
    for (pub_v, priv_v, chal_v) in triples {
        file.write_all(&(pub_v.len() as u64).to_le_bytes())?;
        file.write_all(&(priv_v.len() as u64).to_le_bytes())?;
        file.write_all(&(chal_v.len() as u64).to_le_bytes())?;
    }
    {
        let p = file.stream_position()?;
        pad_to(file, round_up(p, MMAP_ALIGN as u64))?;
    }

    for which in 0..3 {
        for triple in triples {
            let v = match which {
                0 => &triple.0,
                1 => &triple.1,
                _ => &triple.2,
            };
            let bytes = unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 8) };
            file.write_all(bytes)?;
        }
        {
            let p = file.stream_position()?;
            pad_to(file, round_up(p, MMAP_ALIGN as u64))?;
        }
    }

    Ok(file.stream_position()?)
}

/// Read the commitment-info chunk back via memcpy. Returns the triples
/// and the number of bytes consumed.
pub fn read_commitment_info_chunk(bytes: &[u8]) -> Result<(Vec<CommitmentInfoTriple>, usize)> {
    ensure!(bytes.len() >= 8, "ci chunk too short");
    ensure!(bytes[..4] == CI_CHUNK_MAGIC, "ci chunk magic mismatch");
    let mut pos = 8usize;
    let read_u64 = |bytes: &[u8], pos: &mut usize| -> Result<u64> {
        ensure!(*pos + 8 <= bytes.len(), "ci chunk: short read for u64");
        let v = u64::from_le_bytes(bytes[*pos..*pos + 8].try_into().unwrap());
        *pos += 8;
        Ok(v)
    };

    let num_commitments = read_u64(bytes, &mut pos)? as usize;
    let mut lens: Vec<(usize, usize, usize)> = Vec::with_capacity(num_commitments);
    for _ in 0..num_commitments {
        let p = read_u64(bytes, &mut pos)? as usize;
        let pr = read_u64(bytes, &mut pos)? as usize;
        let ch = read_u64(bytes, &mut pos)? as usize;
        lens.push((p, pr, ch));
    }
    pos = round_up(pos as u64, MMAP_ALIGN as u64) as usize;

    let mut pub_vecs = Vec::with_capacity(num_commitments);
    for &(p, ..) in &lens {
        ensure!(pos + p * 8 <= bytes.len(), "ci chunk: short pub");
        let s: &[u64] =
            unsafe { std::slice::from_raw_parts(bytes.as_ptr().add(pos) as *const u64, p) };
        pub_vecs.push(s.to_vec());
        pos += p * 8;
    }
    pos = round_up(pos as u64, MMAP_ALIGN as u64) as usize;

    let mut priv_vecs = Vec::with_capacity(num_commitments);
    for &(_, pr, _) in &lens {
        ensure!(pos + pr * 8 <= bytes.len(), "ci chunk: short priv");
        let s: &[u64] =
            unsafe { std::slice::from_raw_parts(bytes.as_ptr().add(pos) as *const u64, pr) };
        priv_vecs.push(s.to_vec());
        pos += pr * 8;
    }
    pos = round_up(pos as u64, MMAP_ALIGN as u64) as usize;

    let mut chal_vecs = Vec::with_capacity(num_commitments);
    for &(_, _, ch) in &lens {
        ensure!(pos + ch * 8 <= bytes.len(), "ci chunk: short chal");
        let s: &[u64] =
            unsafe { std::slice::from_raw_parts(bytes.as_ptr().add(pos) as *const u64, ch) };
        chal_vecs.push(s.to_vec());
        pos += ch * 8;
    }
    pos = round_up(pos as u64, MMAP_ALIGN as u64) as usize;

    let triples: Vec<CommitmentInfoTriple> = pub_vecs
        .into_iter()
        .zip(priv_vecs.into_iter())
        .zip(chal_vecs.into_iter())
        .map(|((p, pr), ch)| (p, pr, ch))
        .collect();

    Ok((triples, pos))
}

/// Open a file and validate it is a mmap-format `.pkp` (i.e. has the
/// [`MMAP_SENTINEL`] following the 21-byte common header). Returns the open
/// file handle and the offset within it where the postcard metadata starts.
///
/// Used by the prover crate to coordinate metadata + section-body reads off
/// the same file.
pub fn open_mmap_pkp(path: &Path) -> Result<(File, u64)> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    // Skip the 21-byte common header (caller has already validated it via
    // `provekit_common::binary_format`).
    file.seek(SeekFrom::Start(21))?;
    let mut sentinel = [0u8; 4];
    file.read_exact(&mut sentinel)?;
    ensure!(
        sentinel == MMAP_SENTINEL,
        "not an mmap-format .pkp (sentinel mismatch)"
    );
    Ok((file, 25))
}

#[cfg(test)]
mod tests {
    use {super::*, ark_ec::AffineRepr, provekit_common::R1CS, tempfile::tempdir};

    /// Round-trip: setup a tiny PK, write its sections via
    /// `write_pk_sections` into a bare file, then mmap-load and assert the
    /// big arrays match byte-for-byte (and the small scalars equal their
    /// originals). This is the format-stability test for the on-disk layout.
    #[test]
    fn test_mmap_pk_roundtrip() {
        // Trivial circuit: x * x = y
        let mut r1cs = R1CS::new();
        r1cs.num_public_inputs = 1;
        r1cs.add_witnesses(3);
        let one = ark_bn254::Fr::from(1u64);
        r1cs.add_constraint(&[(one, 2)], &[(one, 2)], &[(one, 1)]);
        let (pk, _vk) = crate::setup::setup(&r1cs, &[], &[]).unwrap();

        let dir = tempdir().unwrap();
        let path = dir.path().join("pk_sections.bin");

        // Layout the test file as: [section_count + table + bodies] starting
        // at offset 0, matching what `MmapProvingKey::load(mmap, 0)` expects.
        {
            let mut f = File::create(&path).unwrap();
            write_pk_sections(&pk, &mut f).unwrap();
            f.sync_all().unwrap();
        }

        let file = std::fs::File::open(&path).unwrap();
        let mmap = unsafe { Mmap::map(&file).unwrap() };
        let loaded = MmapProvingKey::load(mmap, 0).unwrap();

        // Big arrays: bytewise equality between the live PK and the
        // mmap-loaded view.
        assert_eq!(loaded.g1_a().len(), pk.g1_a.len(), "g1_a length");
        assert_eq!(loaded.g1_a(), pk.g1_a.as_slice(), "g1_a contents");
        assert_eq!(loaded.g1_b(), pk.g1_b.as_slice(), "g1_b contents");
        assert_eq!(loaded.g1_z(), pk.g1_z.as_slice(), "g1_z contents");
        assert_eq!(loaded.g1_k(), pk.g1_k.as_slice(), "g1_k contents");
        assert_eq!(loaded.g2_b(), pk.g2_b.as_slice(), "g2_b contents");
        assert_eq!(loaded.infinity_a(), pk.infinity_a.as_slice());
        assert_eq!(loaded.infinity_b(), pk.infinity_b.as_slice());

        // Small scalars / individual points.
        assert_eq!(loaded.domain_size, pk.domain_size);
        assert_eq!(loaded.domain_gen, pk.domain_gen);
        assert_eq!(loaded.g1_alpha, pk.g1_alpha);
        assert_eq!(loaded.g1_beta, pk.g1_beta);
        assert_eq!(loaded.g1_delta, pk.g1_delta);
        assert_eq!(loaded.g2_beta, pk.g2_beta);
        assert_eq!(loaded.g2_delta, pk.g2_delta);
        assert_eq!(loaded.nb_infinity_a, pk.nb_infinity_a);
        assert_eq!(loaded.nb_infinity_b, pk.nb_infinity_b);
        assert_eq!(loaded.commitment_keys.len(), pk.commitment_keys.len());

        // Sanity: the points are still on the curve after the mmap cast.
        for p in loaded.g1_a() {
            assert!(p.is_on_curve() || p.is_zero());
        }
    }

    #[test]
    fn test_section_id_roundtrip() {
        for sid in [
            SectionId::G1A,
            SectionId::G1B,
            SectionId::G1Z,
            SectionId::G1K,
            SectionId::G2B,
            SectionId::InfinityA,
            SectionId::InfinityB,
            SectionId::Scalars,
            SectionId::PedersenIndex,
            SectionId::PedersenBases,
            SectionId::PedersenBasesExpSigma,
        ] {
            let v = sid as u32;
            assert_eq!(SectionId::from_u32(v), Some(sid));
        }
        assert_eq!(SectionId::from_u32(0), None);
        assert_eq!(SectionId::from_u32(99), None);
    }
}
