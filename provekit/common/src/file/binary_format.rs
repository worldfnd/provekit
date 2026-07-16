pub const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";

/// Header layout: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) + HASH_CONFIG(1) =
/// 21 bytes
pub const HEADER_SIZE: usize = 21;

/// Zstd magic number: `28 B5 2F FD`.
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// XZ magic number: `FD 37 7A 58 5A 00`.
pub const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];

// ---------------------------------------------------------------------------
// Per-format identifiers and versions
//
// Major must match exactly on read (an incompatible layout is rejected); a
// reader accepts any file whose minor is >= its own.
// ---------------------------------------------------------------------------

pub const PROVER_FORMAT: [u8; 8] = *b"PrvKitPr";
pub const PROVER_VERSION: (u16, u16) = (2, 0);

pub const VERIFIER_FORMAT: [u8; 8] = *b"PrvKitVr";
pub const VERIFIER_VERSION: (u16, u16) = (2, 1);

pub const NOIR_PROOF_SCHEME_FORMAT: [u8; 8] = *b"NrProScm";
pub const NOIR_PROOF_SCHEME_VERSION: (u16, u16) = (2, 0);

pub const NOIR_PROOF_FORMAT: [u8; 8] = *b"NPSProof";
pub const NOIR_PROOF_VERSION: (u16, u16) = (2, 0);

pub const SPARK_PROOF_FORMAT: [u8; 8] = *b"SparkPrf";
pub const SPARK_PROOF_VERSION: (u16, u16) = (1, 0);

pub const SPARK_CONTEXT_FORMAT: [u8; 8] = *b"SparkCtx";
pub const SPARK_CONTEXT_VERSION: (u16, u16) = (1, 0);
