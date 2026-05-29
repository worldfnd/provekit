//! Mmap-backed `.pkp` I/O — a rapidsnark-style alternative to the
//! zstd-compressed legacy path in [`crate::pkp_io`].
//!
//! The two formats coexist under the same `.pkp` extension; they're
//! distinguished by a 4-byte sentinel that follows the 21-byte common header
//! ([`provekit_groth16::mmap_pk::MMAP_SENTINEL`] = `b"MMAP"`). The legacy
//! reader sees zstd / xz magic; the mmap reader sees `MMAP`. Either reader
//! can detect the wrong format and bail out, and [`crate::pkp_io::read_pkp`]
//! auto-dispatches to the right one.
//!
//! ## Layout (recap, see `provekit_groth16::mmap_pk` for full detail)
//!
//! ```text
//! [ HEADER (21 bytes, common with legacy)              ]
//! [ MMAP_SENTINEL "MMAP" (4 bytes)                     ]
//! [ metadata_len (u64 LE, 8 bytes)                     ]
//! [ postcard-encoded Prover (PK/r1cs/commitment_info all zero-byte placeholders) ]
//! [ pad to 8                                           ]
//! [ section table + section bodies (PK + Pedersen, raw layout) ]
//! [ R1CS chunk (raw byte layout — read via memcpy)     ]
//! [ commitment_info chunk (raw byte layout — read via memcpy) ]
//! ```
//!
//! ## Why mmap
//!
//! The legacy path zstd-decompresses + arkworks-deserializes the proving key
//! at startup, which materializes hundreds of megabytes in RAM and runs a
//! per-point Montgomery conversion. The mmap path stores curve points in
//! their in-memory Montgomery layout and exposes `&[G1Affine]` slices that
//! point directly at file pages. The kernel pages bytes in lazily as the MSM
//! touches them — same trick rapidsnark uses for its zkey loader.
//!
//! ## When to use which writer
//!
//! - [`crate::pkp_io::write_pkp`] (zstd): smaller artifact, slower load,
//!   portable across arkworks versions (canonical-bytes serialization).
//! - [`write_pkp_mmap`] (this module): larger artifact (no compression),
//!   near-instant load, file format coupled to the current arkworks in-memory
//!   layout.
//!
//! Both write the same `.pkp` extension. Pick based on whether load time or
//! artifact size matters more for your deployment.

use {
    crate::prover_types::{Groth16PkSource, Groth16Prover, Prover},
    acir::circuit::Program,
    anyhow::{bail, ensure, Context, Result},
    bytes::BufMut as _,
    memmap2::Mmap,
    provekit_common::{
        binary_format::{HEADER_SIZE, MAGIC_BYTES, PROVER_FORMAT, PROVER_VERSION},
        file::MaybeHashAware,
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        NoirElement, R1CS,
    },
    provekit_groth16::mmap_pk::{MmapProvingKey, MMAP_SENTINEL},
    std::{
        fs::{File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        path::Path,
        sync::Arc,
    },
    tracing::{info, info_span, instrument},
};

/// Write a `Prover::Groth16(...)` to disk in the mmap-friendly `.pkp` layout.
///
/// Errors if the prover is not the Groth16 variant, or if its PK source is
/// already mmap-backed (the latter would require copying mmap'd bytes back
/// out, which is supported but currently rejected — call [`crate::pkp_io::
/// write_pkp`] for those edge cases).
#[instrument(skip(prover), fields(path = %path.display()))]
pub fn write_pkp_mmap(prover: &Prover, path: &Path) -> Result<()> {
    let groth16 = match prover {
        Prover::Groth16(g) => g,
        _ => bail!("write_pkp_mmap: only the Groth16 prover variant is supported"),
    };
    let pk = match &groth16.groth16_pk {
        Groth16PkSource::Owned(pk) => pk,
        Groth16PkSource::Mmap(_) => bail!(
            "write_pkp_mmap: source PK is already mmap-backed; rewriting from mmap is not \
             supported"
        ),
    };

    let mut file = File::create(path).context("creating mmap pkp file")?;

    // 1. Common 21-byte header (same as legacy format).
    let hash_config = prover.maybe_hash_config();
    let (major, minor) = PROVER_VERSION;
    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.put(MAGIC_BYTES);
    header.put(&PROVER_FORMAT[..]);
    header.put_u16_le(major);
    header.put_u16_le(minor);
    header.put_u8(hash_config.map(|c| c.to_byte()).unwrap_or(0xff));
    file.write_all(&header).context("writing pkp header")?;

    // 2. Mmap sentinel (4 bytes).
    file.write_all(&MMAP_SENTINEL)
        .context("writing mmap sentinel")?;

    // 3. Postcard-encoded Prover metadata. The PK serializes as zero bytes
    //    (Groth16PkSource::Serialize emits a unit), so the metadata blob is small
    //    (R1CS + builders + ABI).
    let metadata = postcard::to_allocvec(prover).context("postcard-encoding Prover metadata")?;
    file.write_all(&(metadata.len() as u64).to_le_bytes())
        .context("writing metadata length")?;
    file.write_all(&metadata)
        .context("writing postcard metadata")?;

    // 4. Pad to 8-byte alignment so the section table starts cleanly.
    let cur = file.stream_position()?;
    let aligned = (cur + 7) / 8 * 8;
    if aligned > cur {
        let pad = vec![0u8; (aligned - cur) as usize];
        file.write_all(&pad).context("padding to 8-byte align")?;
    }

    // 5. Section table + section bodies (raw Montgomery layout for big arrays).
    //    Delegated to the groth16 crate so the format-on-disk convention lives next
    //    to `MmapProvingKey::load`.
    provekit_groth16::mmap_pk::write_pk_sections(pk, &mut file)
        .context("writing mmap section bodies")?;

    // 6. R1CS chunk (raw byte layout — read via memcpy, no postcard decode). Lives
    //    after the PK section bodies because the PK section writer is monolithic
    //    and easier left untouched.
    provekit_groth16::mmap_pk::write_r1cs_chunk(&groth16.r1cs, &mut file)
        .context("writing mmap r1cs chunk")?;

    // 7. Commitment-info chunk: convert each Groth16CommitmentInfo's Vec<usize>
    //    fields into Vec<u64> for portability and write as raw byte layout.
    let ci_triples: Vec<provekit_groth16::mmap_pk::CommitmentInfoTriple> = groth16
        .commitment_info
        .iter()
        .map(|ci| {
            (
                ci.public_committed.iter().map(|&x| x as u64).collect(),
                ci.private_committed.iter().map(|&x| x as u64).collect(),
                ci.challenge_indices.iter().map(|&x| x as u64).collect(),
            )
        })
        .collect();
    provekit_groth16::mmap_pk::write_commitment_info_chunk(&ci_triples, &mut file)
        .context("writing mmap commitment_info chunk")?;

    file.sync_all().context("syncing mmap pkp file")?;
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    info!(?path, size, "Wrote mmap .pkp");
    Ok(())
}

/// Read a `.pkp` file written by [`write_pkp_mmap`]. The file is mmap'd, the
/// metadata is postcard-decoded out of the mmap, and the proving key is
/// constructed as [`Groth16PkSource::Mmap`] — slices pointing at file pages,
/// no copy.
#[instrument(fields(path = %path.display()))]
pub fn read_pkp_mmap(path: &Path) -> Result<Prover> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;

    // SAFETY: `Mmap::map` requires that the file is not modified while
    // mapped. We open read-only and never expose the mmap to writers; the
    // file may still be modified by another process out-of-band, which is a
    // mode rapidsnark accepts too. Document it and move on.
    let mmap = {
        let _s = info_span!("mmap_map").entered();
        // SAFETY: see the doc comment above. We open read-only and never
        // hand out a writable view.
        unsafe { Mmap::map(&file).with_context(|| format!("mmap'ing {}", path.display()))? }
    };

    // Match rapidsnark's `madvise(MADV_SEQUENTIAL)` from
    // rapidsnark/src/fileloader.cpp:50 — hint the kernel that the bulk
    // curve-point sections will be streamed through during MSM/FFT, so it
    // prefetches aggressively and discards pages we've already read past.
    // Non-fatal if it fails: the worst case is the current behaviour
    // (MADV_NORMAL).
    #[cfg(unix)]
    {
        let _s = info_span!("mmap_advise_sequential").entered();
        if let Err(e) = mmap.advise(memmap2::Advice::Sequential) {
            tracing::debug!("mmap advise(Sequential) failed (non-fatal): {e}");
        }
    }

    ensure!(
        mmap.len() >= HEADER_SIZE + 4 + 8,
        "mmap pkp: file too short for header+sentinel+metadata_len"
    );

    // 1. Validate the 21-byte common header.
    let header = &mmap[..HEADER_SIZE];
    ensure!(
        &header[0..8] == MAGIC_BYTES,
        "mmap pkp: invalid magic bytes"
    );
    ensure!(
        header[8..16] == PROVER_FORMAT,
        "mmap pkp: invalid format id"
    );
    let file_major = u16::from_le_bytes([header[16], header[17]]);
    let file_minor = u16::from_le_bytes([header[18], header[19]]);
    ensure!(
        file_major == PROVER_VERSION.0,
        "mmap pkp: incompatible major version (file v{}.{}, build expects v{}.{})",
        file_major,
        file_minor,
        PROVER_VERSION.0,
        PROVER_VERSION.1
    );
    ensure!(
        file_minor >= PROVER_VERSION.1,
        "mmap pkp: incompatible minor version (file v{}.{}, build requires v{}.{}+)",
        file_major,
        file_minor,
        PROVER_VERSION.0,
        PROVER_VERSION.1
    );

    // 2. Sentinel.
    ensure!(
        mmap[HEADER_SIZE..HEADER_SIZE + 4] == MMAP_SENTINEL,
        "mmap pkp: missing MMAP sentinel (this is not an mmap-format .pkp)"
    );
    let mut pos = HEADER_SIZE + 4;

    // 3. Metadata length, then postcard-decode the Prover.
    let metadata_len = u64::from_le_bytes(mmap[pos..pos + 8].try_into().unwrap()) as usize;
    pos += 8;
    ensure!(
        pos + metadata_len <= mmap.len(),
        "mmap pkp: metadata extends past file end"
    );
    let metadata_bytes = &mmap[pos..pos + metadata_len];
    pos += metadata_len;
    // The mmap path is Groth16-only. Decode each field of the inner
    // `Groth16Prover` one at a time via `postcard::take_from_bytes` so
    // each field's cost shows up as its own span. `r1cs` and
    // `commitment_info` are `#[serde(skip)]`, so the wire-order is:
    //   variant_tag, program, split_witness_builders, witness_generator,
    // groth16_pk.
    let mut prover: Prover = {
        let _s = info_span!("postcard_decode_prover", metadata_len).entered();

        let (variant_tag, rest): (u32, &[u8]) =
            postcard::take_from_bytes(metadata_bytes).context("reading Prover variant tag")?;
        ensure!(
            variant_tag == 2,
            "mmap pkp: expected Groth16 variant (tag 2), got tag {}",
            variant_tag
        );

        let (program, rest): (Program<NoirElement>, &[u8]) = {
            let _s = info_span!("postcard_program").entered();
            postcard::take_from_bytes(rest).context("decoding program")?
        };
        let (split_witness_builders, rest): (SplitWitnessBuilders, &[u8]) = {
            let _s = info_span!("postcard_split_witness_builders").entered();
            postcard::take_from_bytes(rest).context("decoding split_witness_builders")?
        };
        let (witness_generator, rest): (NoirWitnessGenerator, &[u8]) = {
            let _s = info_span!("postcard_witness_generator").entered();
            postcard::take_from_bytes(rest).context("decoding witness_generator")?
        };
        let (groth16_pk, _): (Groth16PkSource, &[u8]) = {
            let _s = info_span!("postcard_groth16_pk_placeholder").entered();
            postcard::take_from_bytes(rest).context("decoding groth16_pk placeholder")?
        };

        Prover::Groth16(Groth16Prover {
            program,
            r1cs: R1CS::default(),
            split_witness_builders,
            witness_generator,
            groth16_pk,
            commitment_info: Vec::new(),
        })
    };

    // 4. Pad to 8-byte alignment for the section table start.
    pos = (pos + 7) / 8 * 8;

    // 5. Read R1CS chunk from the mmap (memcpy into owned R1CS). This must happen
    //    BEFORE `MmapProvingKey::load` consumes the mmap. The chunk starts
    //    immediately after the PK section bodies; we walk the PK section table to
    //    find that offset.
    let pk_end = {
        let _s = info_span!("pk_sections_end_offset").entered();
        provekit_groth16::mmap_pk::pk_sections_end_offset(&mmap, pos)
            .context("finding end of PK sections")?
    };
    let (r1cs_loaded, r1cs_end) = {
        let _s = info_span!("read_r1cs_chunk").entered();
        let (r1cs, consumed) = provekit_groth16::mmap_pk::read_r1cs_chunk(&mmap[pk_end..])
            .context("reading r1cs chunk")?;
        (r1cs, pk_end + consumed)
    };
    let ci_triples = {
        let _s = info_span!("read_commitment_info_chunk").entered();
        let (triples, _consumed) =
            provekit_groth16::mmap_pk::read_commitment_info_chunk(&mmap[r1cs_end..])
                .context("reading commitment_info chunk")?;
        triples
    };

    // 6. Construct the MmapProvingKey from the section bodies.
    let mmap_pk = {
        let _s = info_span!("mmap_pk_load").entered();
        MmapProvingKey::load(mmap, pos).context("loading mmap-backed proving key sections")?
    };

    // 7. Replace the placeholder PK source, populate r1cs from memcpy, convert
    //    commitment_info triples back to the prover-side type.
    match &mut prover {
        Prover::Groth16(g) => {
            g.groth16_pk = Groth16PkSource::Mmap(Arc::new(mmap_pk));
            g.r1cs = r1cs_loaded;
            g.commitment_info = ci_triples
                .into_iter()
                .map(
                    |(pub_v, priv_v, chal_v)| crate::prover_types::Groth16CommitmentInfo {
                        public_committed:  pub_v.into_iter().map(|x| x as usize).collect(),
                        private_committed: priv_v.into_iter().map(|x| x as usize).collect(),
                        challenge_indices: chal_v.into_iter().map(|x| x as usize).collect(),
                    },
                )
                .collect();
        }
        _ => bail!("mmap pkp: metadata decoded as non-Groth16 prover variant"),
    }

    Ok(prover)
}

/// Peek the first bytes of a `.pkp` file to check whether it's the mmap
/// format (returns `true`) or the legacy zstd/xz format (returns `false`).
/// Returns an error only if the file can't be read or is shorter than the
/// header.
pub fn is_mmap_pkp(path: &Path) -> Result<bool> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
    let mut sentinel = [0u8; 4];
    let n = file.read(&mut sentinel)?;
    if n < 4 {
        return Ok(false);
    }
    Ok(sentinel == MMAP_SENTINEL)
}
