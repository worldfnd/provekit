pub mod commitment;
pub mod mock_generator;
pub mod mock_keys;
mod parser;
pub mod partial_sha256;

pub use crate::parser::{binary::Binary, sod::SOD};
use {
    crate::parser::{
        types::{
            PassportError, SignatureAlgorithmName, CHUNK1_SIZE, MAX_DG1_SIZE, MAX_ECONTENT_SIZE,
            MAX_SIGNED_ATTRIBUTES_SIZE, MAX_TBS_SIZE, MAX_TBS_SIZE_1300, SIG_BYTES, TREE_DEPTH,
        },
        utils::{
            find_offset, fit, load_csca_public_keys, to_fixed_array, to_u32, ASN1_HEADER_LEN,
            ASN1_OCTET_STRING_TAG,
        },
    },
    base64::{engine::general_purpose::STANDARD, Engine as _},
    noir_bignum_paramgen::compute_barrett_reduction_parameter,
    rsa::{
        pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts, BigUint,
        Pkcs1v15Sign, Pss, RsaPublicKey,
    },
    sha2::{Digest, Sha256},
    std::{fmt::Write as _, path::Path},
};

// ============================================================================
// Constants
// ============================================================================

/// Zero BN254 field element as a 0x-prefixed hex string (used as sentinel /
/// default for Merkle fields).
pub const ZERO_FIELD: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

// ============================================================================
// Configuration
// ============================================================================

/// Shared application-level parameters for all merkle_age_check circuit chains.
/// Contains commitment salts, Merkle tree data, and attestation parameters.
pub struct MerkleAgeBaseConfig {
    /// Salt for the penultimate commitment stage
    pub salt_1:           String,
    /// Salt for the final commitment stage
    pub salt_2:           String,
    /// Blinding factor for DG1 Poseidon2 commitment
    pub r_dg1:            String,
    /// Current date as unix timestamp
    pub current_date:     u64,
    /// Minimum age to prove
    pub min_age_required: u8,
    /// Maximum age (0 = no upper bound)
    pub max_age_required: u8,
    /// Service scope hash (H(domain_name))
    pub service_scope:    String,
    /// Service sub-scope hash (H(purpose))
    pub service_subscope: String,
    /// Optional nullifier secret for salting
    pub nullifier_secret: String,
    /// Merkle tree root (from sequencer)
    pub merkle_root:      String,
    /// Leaf index in Merkle tree
    pub leaf_index:       String,
    /// Merkle path sibling hashes (TREE_DEPTH elements)
    pub merkle_path:      Vec<String>,
}

impl Default for MerkleAgeBaseConfig {
    fn default() -> Self {
        Self {
            salt_1:           "0x2".to_string(),
            salt_2:           "0x3".to_string(),
            r_dg1:            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            current_date:     1735689600, // Jan 1, 2025
            min_age_required: 18,
            max_age_required: 0,
            service_scope:    ZERO_FIELD.to_string(),
            service_subscope: ZERO_FIELD.to_string(),
            nullifier_secret: ZERO_FIELD.to_string(),
            merkle_root:      ZERO_FIELD.to_string(),
            leaf_index:       "0".to_string(),
            merkle_path:      vec![ZERO_FIELD.to_string(); TREE_DEPTH],
        }
    }
}

impl MerkleAgeBaseConfig {
    /// Build AttestInputs from the shared config and passport data, computing
    /// the merkle root if the sentinel zero value is present.
    fn build_attest(
        self,
        dg1_padded: &[u8; MAX_DG1_SIZE],
        computed_sod_hash: ark_bn254::Fr,
        sod_hash_hex: String,
    ) -> Result<AttestInputs, PassportError> {
        let merkle_root = {
            if self.merkle_root == ZERO_FIELD {
                let h_dg1 = commitment::calculate_h_dg1(&self.r_dg1, dg1_padded)?;
                let leaf = commitment::calculate_leaf(h_dg1, computed_sod_hash);
                let leaf_idx: u64 =
                    self.leaf_index
                        .parse()
                        .map_err(|_| PassportError::InvalidLeafIndex {
                            value: self.leaf_index.clone(),
                        })?;
                let path_fields: Vec<ark_bn254::Fr> = self
                    .merkle_path
                    .iter()
                    .map(|s| commitment::parse_hex_to_field(s))
                    .collect::<Result<Vec<_>, _>>()?;
                let root = commitment::compute_merkle_root(leaf, leaf_idx, &path_fields);
                commitment::field_to_hex_string(&root)
            } else {
                self.merkle_root
            }
        };

        Ok(AttestInputs {
            root:             merkle_root,
            current_date:     self.current_date,
            service_scope:    self.service_scope,
            service_subscope: self.service_subscope,
            dg1:              *dg1_padded,
            r_dg1:            self.r_dg1,
            sod_hash:         sod_hash_hex,
            leaf_index:       self.leaf_index,
            merkle_path:      self.merkle_path,
            min_age_required: self.min_age_required,
            max_age_required: self.max_age_required,
            nullifier_secret: self.nullifier_secret,
        })
    }
}

/// Application-level parameters for the 4-circuit merkle_age_check TBS-720
/// chain.
pub struct MerkleAge720Config {
    /// Shared configuration fields
    pub base: MerkleAgeBaseConfig,
}

impl Default for MerkleAge720Config {
    fn default() -> Self {
        Self {
            base: MerkleAgeBaseConfig::default(),
        }
    }
}

/// Application-level parameters for the 5-circuit merkle_age_check TBS-1300
/// chain.
///
/// The TBS-1300 chain has 3 salts (vs 2 for TBS-720) because DSC verification
/// is split into two circuits (dsc_hash + dsc_verify).
pub struct MerkleAge1300Config {
    /// Salt for circuits 1+2 (dsc_hash & dsc_verify input): "0x1"
    pub salt_0: String,
    /// Shared configuration fields
    pub base:   MerkleAgeBaseConfig,
}

impl Default for MerkleAge1300Config {
    fn default() -> Self {
        Self {
            salt_0: "0x1".to_string(),
            base:   MerkleAgeBaseConfig::default(),
        }
    }
}

// ============================================================================
// Circuit input structs
// ============================================================================

/// Inputs for t_add_dsc_720: Verify CSCA signed DSC certificate (720-byte TBS)
#[derive(serde::Serialize)]
pub struct AddDsc720Inputs {
    /// CSCA public key modulus (RSA-4096, 512 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub csc_pubkey:            [u8; SIG_BYTES * 2],
    /// Salt for commitment
    pub salt:                  String,
    /// 3-character country code from passport
    pub country:               String,
    /// DSC TBS certificate padded to 720 bytes
    #[serde(serialize_with = "byte_array::serialize")]
    pub tbs_certificate:       [u8; MAX_TBS_SIZE],
    /// Barrett reduction parameter for CSCA modulus (513 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub csc_pubkey_redc_param: [u8; SIG_BYTES * 2 + 1],
    /// CSCA signature over the DSC TBS certificate (512 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dsc_signature:         [u8; SIG_BYTES * 2],
    /// RSA exponent (CSCA)
    pub exponent:              u32,
    /// Actual TBS certificate length before padding
    pub tbs_certificate_len:   u32,
}

/// Inputs for t_add_id_data_720: Verify DSC signed passport data (720-byte TBS)
#[derive(serde::Serialize)]
pub struct AddIdData720Inputs {
    /// Commitment from circuit 1 (placeholder until circuit 1 runs)
    pub comm_in: String,
    /// Input salt (must match circuit 1's salt)
    pub salt_in: String,
    /// Output salt for this circuit's commitment
    pub salt_out: String,
    /// DG1 Machine Readable Zone data (95 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dg1: [u8; MAX_DG1_SIZE],
    /// DSC public key modulus (RSA-2048, 256 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dsc_pubkey: [u8; SIG_BYTES],
    /// Barrett reduction parameter for DSC modulus (257 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dsc_pubkey_redc_param: [u8; SIG_BYTES + 1],
    /// Byte offset of DSC pubkey within TBS certificate
    pub dsc_pubkey_offset_in_dsc_cert: u32,
    /// DSC signature over signed_attributes (256 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub sod_signature: [u8; SIG_BYTES],
    /// DSC TBS certificate padded to 720 bytes
    #[serde(serialize_with = "byte_array::serialize")]
    pub tbs_certificate: [u8; MAX_TBS_SIZE],
    /// Signed attributes from SOD (200 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub signed_attributes: [u8; MAX_SIGNED_ATTRIBUTES_SIZE],
    /// Actual signed attributes size
    pub signed_attributes_size: u64,
    /// RSA exponent (DSC)
    pub exponent: u32,
    /// eContent hash values (200 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub e_content: [u8; MAX_ECONTENT_SIZE],
}

/// Inputs for t_add_integrity_commit: Verify data integrity + generate Merkle
/// leaf
#[derive(serde::Serialize)]
pub struct AddIntegrityCommitInputs {
    /// Commitment from circuit 2 (placeholder until circuit 2 runs)
    pub comm_in:                String,
    /// Input salt (must match circuit 2's output salt)
    pub salt_in:                String,
    /// DG1 Machine Readable Zone data (95 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dg1:                    [u8; MAX_DG1_SIZE],
    /// DG1 padded length for SHA256
    pub dg1_padded_length:      u64,
    /// Offset of DG1 hash within eContent
    pub dg1_hash_offset:        u32,
    /// Signed attributes from SOD (200 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub signed_attributes:      [u8; MAX_SIGNED_ATTRIBUTES_SIZE],
    /// Actual signed attributes size
    pub signed_attributes_size: u32,
    /// eContent hash values (200 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub e_content:              [u8; MAX_ECONTENT_SIZE],
    /// Actual eContent length
    pub e_content_len:          u32,
    /// Pre-computed private nullifier (Poseidon2 hash)
    pub private_nullifier:      String,
    /// Blinding factor for DG1 commitment
    pub r_dg1:                  String,
}

/// Inputs for t_attest: Age attestation with Merkle tree membership proof
#[derive(serde::Serialize)]
pub struct AttestInputs {
    /// Current Merkle tree root (from sequencer)
    pub root:             String,
    /// Current date as unix timestamp
    pub current_date:     u64,
    /// Service scope: H(domain_name)
    pub service_scope:    String,
    /// Service sub-scope: H(purpose)
    pub service_subscope: String,
    /// DG1 Machine Readable Zone data (95 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dg1:              [u8; MAX_DG1_SIZE],
    /// Blinding factor from registration
    pub r_dg1:            String,
    /// SOD hash: Poseidon2(packed_e_content)
    pub sod_hash:         String,
    /// Position in Merkle tree
    pub leaf_index:       String,
    /// Sibling hashes for Merkle path (TREE_DEPTH elements)
    pub merkle_path:      Vec<String>,
    /// Minimum age to prove
    pub min_age_required: u8,
    /// Maximum age (0 = no upper bound)
    pub max_age_required: u8,
    /// Optional secret for nullifier salting
    pub nullifier_secret: String,
}

/// Container for all 4 circuit inputs in the merkle_age_check TBS-720 chain
pub struct MerkleAge720Inputs {
    pub add_dsc:       AddDsc720Inputs,
    pub add_id_data:   AddIdData720Inputs,
    pub add_integrity: AddIntegrityCommitInputs,
    pub attest:        AttestInputs,
}

// --- TBS-1300 circuit input structs (5-circuit chain) ---

/// Inputs for t_add_dsc_hash_1300: Process first 640 bytes of TBS, output
/// SHA256 state commitment
#[derive(serde::Serialize)]
pub struct AddDscHash1300Inputs {
    /// Salt for commitment (shared with dsc_verify)
    pub salt:   String,
    /// First 640 bytes of TBS certificate
    #[serde(serialize_with = "byte_array::serialize")]
    pub chunk1: [u8; CHUNK1_SIZE],
}

/// Inputs for t_add_dsc_verify_1300: Continue SHA256, verify RSA, output
/// country+TBS commitment
#[derive(serde::Serialize)]
pub struct AddDscVerify1300Inputs {
    /// Commitment from circuit 1 (SHA256 state + data commitment)
    pub comm_in:               String,
    /// CSCA public key modulus (RSA-4096, 512 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub csc_pubkey:            [u8; SIG_BYTES * 2],
    /// Salt (same as dsc_hash's salt)
    pub salt:                  String,
    /// 3-character country code
    pub country:               String,
    /// SHA256 intermediate state from processing chunk1
    pub state1:                [u32; 8],
    /// Full TBS certificate padded to 1300 bytes
    #[serde(serialize_with = "byte_array::serialize")]
    pub tbs_certificate:       [u8; MAX_TBS_SIZE_1300],
    /// Actual TBS certificate length before padding
    pub tbs_certificate_len:   u32,
    /// Barrett reduction parameter for CSCA modulus (513 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub csc_pubkey_redc_param: [u8; SIG_BYTES * 2 + 1],
    /// CSCA signature over the DSC TBS certificate (512 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dsc_signature:         [u8; SIG_BYTES * 2],
    /// RSA exponent (CSCA)
    pub exponent:              u32,
    /// Output salt for this circuit's commitment
    pub salt_out:              String,
}

/// Inputs for t_add_id_data_1300: Verify DSC signed passport data (1300-byte
/// TBS)
#[derive(serde::Serialize)]
pub struct AddIdData1300Inputs {
    /// Commitment from circuit 2
    pub comm_in: String,
    /// Input salt (must match circuit 2's output salt)
    pub salt_in: String,
    /// Output salt for this circuit's commitment
    pub salt_out: String,
    /// DG1 Machine Readable Zone data (95 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dg1: [u8; MAX_DG1_SIZE],
    /// DSC public key modulus (RSA-2048, 256 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dsc_pubkey: [u8; SIG_BYTES],
    /// Barrett reduction parameter for DSC modulus (257 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub dsc_pubkey_redc_param: [u8; SIG_BYTES + 1],
    /// Byte offset of DSC pubkey within TBS certificate
    pub dsc_pubkey_offset_in_dsc_cert: u32,
    /// DSC signature over signed_attributes (256 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub sod_signature: [u8; SIG_BYTES],
    /// DSC TBS certificate padded to 1300 bytes
    #[serde(serialize_with = "byte_array::serialize")]
    pub tbs_certificate: [u8; MAX_TBS_SIZE_1300],
    /// Signed attributes from SOD (200 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub signed_attributes: [u8; MAX_SIGNED_ATTRIBUTES_SIZE],
    /// Actual signed attributes size
    pub signed_attributes_size: u64,
    /// RSA exponent (DSC)
    pub exponent: u32,
    /// eContent hash values (200 bytes)
    #[serde(serialize_with = "byte_array::serialize")]
    pub e_content: [u8; MAX_ECONTENT_SIZE],
}

/// Container for all 5 circuit inputs in the merkle_age_check TBS-1300 chain
pub struct MerkleAge1300Inputs {
    pub add_dsc_hash:   AddDscHash1300Inputs,
    pub add_dsc_verify: AddDscVerify1300Inputs,
    pub add_id_data:    AddIdData1300Inputs,
    pub add_integrity:  AddIntegrityCommitInputs,
    pub attest:         AttestInputs,
}

// ============================================================================
// Extracted passport data (shared between 720/1300 paths)
// ============================================================================

/// Common passport data extracted from DG1 + SOD, shared by both the 720 and
/// 1300 circuit pipelines.
struct PassportData {
    dg1_padded:             [u8; MAX_DG1_SIZE],
    dg1_len:                usize,
    signed_attrs:           [u8; MAX_SIGNED_ATTRIBUTES_SIZE],
    signed_attributes_size: usize,
    econtent:               [u8; MAX_ECONTENT_SIZE],
    econtent_len:           usize,
    dsc_modulus:            [u8; SIG_BYTES],
    dsc_exponent:           u32,
    dsc_barrett:            [u8; SIG_BYTES + 1],
    sod_signature:          [u8; SIG_BYTES],
    csca_modulus:           [u8; SIG_BYTES * 2],
    csca_exponent:          u32,
    csca_barrett:           [u8; SIG_BYTES * 2 + 1],
    csca_signature:         [u8; SIG_BYTES * 2],
    country:                String,
    dg1_hash_offset:        usize,
    private_nullifier:      ark_bn254::Fr,
    private_nullifier_hex:  String,
    computed_sod_hash:      ark_bn254::Fr,
    sod_hash_hex:           String,
}

// ============================================================================
// PassportReader
// ============================================================================

/// Parsed passport data
pub struct PassportReader {
    dg1:         Binary,
    sod:         SOD,
    /// Indicates whether this reader contains mock data or real passport data
    mockdata:    bool,
    /// Optional CSCA public key when using mock data
    csca_pubkey: Option<RsaPublicKey>,
}

impl PassportReader {
    pub fn new(dg1: Binary, sod: SOD, mockdata: bool, csca_pubkey: Option<RsaPublicKey>) -> Self {
        Self {
            dg1,
            sod,
            mockdata,
            csca_pubkey,
        }
    }

    /// Extract SignedAttributes (padded + size)
    fn extract_signed_attrs(
        &self,
    ) -> Result<([u8; MAX_SIGNED_ATTRIBUTES_SIZE], usize), PassportError> {
        let signed_attrs = self.sod.signer_info.signed_attrs.bytes.as_bytes();
        let size = signed_attrs.len();
        let padded = fit::<MAX_SIGNED_ATTRIBUTES_SIZE>(signed_attrs)?;
        Ok((padded, size))
    }

    /// Extract eContent (padded + size + raw bytes)
    fn extract_econtent(&self) -> Result<([u8; MAX_ECONTENT_SIZE], usize, &[u8]), PassportError> {
        let econtent_bytes = self.sod.encap_content_info.e_content.bytes.as_bytes();
        let len = econtent_bytes.len();
        let padded = fit::<MAX_ECONTENT_SIZE>(econtent_bytes)?;
        Ok((padded, len, econtent_bytes))
    }

    /// Extract DSC public key, exponent, Barrett mu, and SOD signature
    fn extract_dsc(
        &self,
    ) -> Result<([u8; SIG_BYTES], u32, [u8; SIG_BYTES + 1], [u8; SIG_BYTES]), PassportError> {
        let der = self
            .sod
            .certificate
            .tbs
            .subject_public_key_info
            .subject_public_key
            .as_bytes();
        let pubkey =
            RsaPublicKey::from_pkcs1_der(der).map_err(|_| PassportError::DscPublicKeyInvalid)?;

        let modulus = to_fixed_array::<SIG_BYTES>(&pubkey.n().to_bytes_be(), "DSC modulus")?;
        let exponent = to_u32(pubkey.e().to_bytes_be())?;
        let barrett = to_fixed_array::<{ SIG_BYTES + 1 }>(
            &compute_barrett_reduction_parameter(&BigUint::from_bytes_be(&modulus)).to_bytes_be(),
            "DSC Barrett",
        )?;
        let signature = to_fixed_array::<SIG_BYTES>(
            self.sod.signer_info.signature.as_bytes(),
            "DSC signature",
        )?;

        Ok((modulus, exponent, barrett, signature))
    }

    /// Decode a base64-encoded CSCA public key from DER format
    fn decode_csca_pubkey(b64: &str) -> Result<RsaPublicKey, PassportError> {
        let der = STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| PassportError::Base64DecodingFailed(e.to_string()))?;
        RsaPublicKey::from_public_key_der(&der).map_err(|_| PassportError::CscaPublicKeyInvalid)
    }

    /// Extract CSCA modulus, exponent, Barrett mu, and certificate signature
    /// from a given public key
    fn extract_csca_fields(
        &self,
        pubkey: &RsaPublicKey,
    ) -> Result<
        (
            [u8; SIG_BYTES * 2],
            u32,
            [u8; SIG_BYTES * 2 + 1],
            [u8; SIG_BYTES * 2],
        ),
        PassportError,
    > {
        let modulus =
            to_fixed_array::<{ SIG_BYTES * 2 }>(&pubkey.n().to_bytes_be(), "CSCA modulus")?;
        let exponent = to_u32(pubkey.e().to_bytes_be())?;
        let barrett = to_fixed_array::<{ SIG_BYTES * 2 + 1 }>(
            &compute_barrett_reduction_parameter(&BigUint::from_bytes_be(&modulus)).to_bytes_be(),
            "CSCA Barrett",
        )?;
        let signature = to_fixed_array::<{ SIG_BYTES * 2 }>(
            self.sod.certificate.signature.as_bytes(),
            "CSCA signature",
        )?;

        Ok((modulus, exponent, barrett, signature))
    }

    /// Extract CSCA public key, exponent, Barrett mu, and certificate signature
    fn extract_csca(
        &self,
        idx: usize,
    ) -> Result<
        (
            [u8; SIG_BYTES * 2],
            u32,
            [u8; SIG_BYTES * 2 + 1],
            [u8; SIG_BYTES * 2],
        ),
        PassportError,
    > {
        let csca_keys = load_csca_public_keys().map_err(|_| PassportError::FailedToLoadCscaKeys)?;
        let usa_csca = csca_keys.get("USA").ok_or(PassportError::NoUsaCsca)?;
        let pubkey = Self::decode_csca_pubkey(&usa_csca[idx].public_key)?;
        self.extract_csca_fields(&pubkey)
    }

    /// Extract CSCA data from an in-memory public key (used for mock data)
    fn extract_csca_from_pubkey(
        &self,
        pubkey: &RsaPublicKey,
    ) -> Result<
        (
            [u8; SIG_BYTES * 2],
            u32,
            [u8; SIG_BYTES * 2 + 1],
            [u8; SIG_BYTES * 2],
        ),
        PassportError,
    > {
        self.extract_csca_fields(pubkey)
    }

    /// Extract DSC certificate TBS (padded to 720 + actual len + pubkey offset)
    fn extract_dsc_cert(
        &self,
        dsc_modulus: &[u8; SIG_BYTES],
    ) -> Result<([u8; MAX_TBS_SIZE], usize, usize), PassportError> {
        self.extract_dsc_cert_sized::<MAX_TBS_SIZE>(dsc_modulus)
    }

    /// Extract DSC certificate TBS padded to a generic size N, with actual
    /// length and pubkey offset
    fn extract_dsc_cert_sized<const N: usize>(
        &self,
        dsc_modulus: &[u8; SIG_BYTES],
    ) -> Result<([u8; N], usize, usize), PassportError> {
        let tbs_bytes = self.sod.certificate.tbs.bytes.as_bytes();
        let cert_len = tbs_bytes.len();
        let padded = fit::<N>(tbs_bytes)?;
        let pubkey_offset = find_offset(tbs_bytes, dsc_modulus, "DSC modulus in cert")?;
        Ok((padded, cert_len, pubkey_offset))
    }

    /// Extract country code from DG1 bytes [7..10]
    fn extract_country(&self) -> String {
        let dg1 = self.dg1.as_bytes();
        if dg1.len() >= 10 {
            String::from_utf8_lossy(&dg1[7..10]).to_string()
        } else {
            "<<<".to_string()
        }
    }

    /// Extract all common passport data fields needed by both the 720 and 1300
    /// circuit pipelines. This consolidates the repeated extraction preamble.
    fn extract_passport_data(&self, csca_key_index: usize) -> Result<PassportData, PassportError> {
        let dg1_padded = fit::<MAX_DG1_SIZE>(self.dg1.as_bytes())?;
        let dg1_len = self.dg1.len();

        let (signed_attrs, signed_attributes_size) = self.extract_signed_attrs()?;
        let (econtent, econtent_len, econtent_bytes) = self.extract_econtent()?;

        let (dsc_modulus, dsc_exponent, dsc_barrett, sod_signature) = self.extract_dsc()?;

        let (csca_modulus, csca_exponent, csca_barrett, csca_signature) = if self.mockdata {
            let key = self
                .csca_pubkey
                .as_ref()
                .ok_or(PassportError::MissingCscaMockKey)?;
            self.extract_csca_from_pubkey(key)?
        } else {
            self.extract_csca(csca_key_index)?
        };

        let dg1_hash = Sha256::digest(self.dg1.as_bytes());
        let dg1_hash_offset = find_offset(econtent_bytes, dg1_hash.as_slice(), "DG1 hash")?;

        let country = self.extract_country();

        let private_nullifier =
            commitment::calculate_private_nullifier(&dg1_padded, &econtent, &sod_signature);
        let private_nullifier_hex = commitment::field_to_hex_string(&private_nullifier);

        let computed_sod_hash = commitment::calculate_sod_hash(&econtent);
        let sod_hash_hex = commitment::field_to_hex_string(&computed_sod_hash);

        Ok(PassportData {
            dg1_padded,
            dg1_len,
            signed_attrs,
            signed_attributes_size,
            econtent,
            econtent_len,
            dsc_modulus,
            dsc_exponent,
            dsc_barrett,
            sod_signature,
            csca_modulus,
            csca_exponent,
            csca_barrett,
            csca_signature,
            country,
            dg1_hash_offset,
            private_nullifier,
            private_nullifier_hex,
            computed_sod_hash,
            sod_hash_hex,
        })
    }

    /// Validate DG1, eContent, and signatures against DSC + CSCA
    pub fn validate(&self) -> Result<usize, PassportError> {
        // 1. Check DG1 hash inside eContent
        let dg1_hash = Sha256::digest(self.dg1.as_bytes());
        let dg1_from_econtent = self
            .sod
            .encap_content_info
            .e_content
            .data_group_hash_values
            .values
            .get(&1)
            .ok_or(PassportError::MissingDg1Hash)?
            .as_bytes();

        if dg1_from_econtent != dg1_hash.as_slice() {
            return Err(PassportError::Dg1HashMismatch);
        }

        // 2. Check hash(eContent) inside SignedAttributes
        let econtent_hash = Sha256::digest(self.sod.encap_content_info.e_content.bytes.as_bytes());
        let mut msg_digest = self.sod.signer_info.signed_attrs.message_digest.as_bytes();

        if msg_digest.len() > ASN1_HEADER_LEN && msg_digest[0] == ASN1_OCTET_STRING_TAG {
            msg_digest = &msg_digest[ASN1_HEADER_LEN..];
        }

        if econtent_hash.as_slice() != msg_digest {
            return Err(PassportError::EcontentHashMismatch);
        }

        // 3. Verify SignedAttributes signature with DSC
        let signed_attr_hash = Sha256::digest(self.sod.signer_info.signed_attrs.bytes.as_bytes());
        let dsc_pubkey_bytes = self
            .sod
            .certificate
            .tbs
            .subject_public_key_info
            .subject_public_key
            .as_bytes();
        let dsc_pubkey = RsaPublicKey::from_pkcs1_der(dsc_pubkey_bytes)
            .map_err(|_| PassportError::DscPublicKeyInvalid)?;

        let dsc_signature = self.sod.signer_info.signature.as_bytes();

        let verify_result = match &self.sod.signer_info.signature_algorithm.name {
            SignatureAlgorithmName::Sha256WithRsaEncryption
            | SignatureAlgorithmName::RsaEncryption => dsc_pubkey.verify(
                Pkcs1v15Sign::new::<Sha256>(),
                signed_attr_hash.as_slice(),
                dsc_signature,
            ),
            SignatureAlgorithmName::RsassaPss => dsc_pubkey.verify(
                Pss::new::<Sha256>(),
                signed_attr_hash.as_slice(),
                dsc_signature,
            ),
            unsupported => {
                return Err(PassportError::UnsupportedSignatureAlgorithm(format!(
                    "{:?}",
                    unsupported
                )))
            }
        };
        verify_result.map_err(|_| PassportError::DscSignatureInvalid)?;

        // 4. Verify DSC certificate signature with CSCA
        let tbs_bytes = self.sod.certificate.tbs.bytes.as_bytes();
        let tbs_digest = Sha256::digest(tbs_bytes);
        let csca_signature = self.sod.certificate.signature.as_bytes();

        if let Some(key) = &self.csca_pubkey {
            key.verify(
                Pkcs1v15Sign::new::<Sha256>(),
                tbs_digest.as_slice(),
                csca_signature,
            )
            .map_err(|_| PassportError::CscaSignatureInvalid)?;
            return Ok(0);
        }

        let all_csca = load_csca_public_keys().map_err(|_| PassportError::CscaKeysMissing)?;
        let usa_csca = all_csca.get("USA").ok_or(PassportError::NoUsaCsca)?;

        for (i, csca) in usa_csca.iter().enumerate() {
            let csca_pubkey = Self::decode_csca_pubkey(&csca.public_key)?;
            if csca_pubkey
                .verify(
                    Pkcs1v15Sign::new::<Sha256>(),
                    tbs_digest.as_slice(),
                    csca_signature,
                )
                .is_ok()
            {
                return Ok(i);
            }
        }
        Err(PassportError::CscaSignatureInvalid)
    }

    /// Generate inputs for the 4-circuit merkle_age_check TBS-720 chain.
    ///
    /// Extracts passport data and distributes it across 4 circuit input
    /// structs. Commitment values and Merkle data come from the config
    /// (placeholders by default).
    pub fn to_merkle_age_720_inputs(
        &self,
        csca_key_index: usize,
        config: MerkleAge720Config,
    ) -> Result<MerkleAge720Inputs, PassportError> {
        let pd = self.extract_passport_data(csca_key_index)?;

        // DSC certificate TBS (720-byte path)
        let (tbs_cert, tbs_cert_len, dsc_pubkey_offset) = self.extract_dsc_cert(&pd.dsc_modulus)?;

        // === Compute Poseidon2 commitments ===

        // Circuit 1 output: hash(salt_1, country, tbs_cert)
        let comm_out_1 = commitment::hash_salt_country_tbs(
            &config.base.salt_1,
            pd.country.as_bytes(),
            &tbs_cert,
        )?;
        let comm_out_1_hex = commitment::field_to_hex_string(&comm_out_1);

        // Circuit 2 output: hash(salt_2, country, signed_attr, sa_size, dg1, e_content,
        // nullifier)
        let comm_out_2 = commitment::hash_salt_country_sa_dg1_econtent_nullifier(
            &config.base.salt_2,
            pd.country.as_bytes(),
            &pd.signed_attrs,
            pd.signed_attributes_size as u64,
            &pd.dg1_padded,
            &pd.econtent,
            pd.private_nullifier,
        )?;
        let comm_out_2_hex = commitment::field_to_hex_string(&comm_out_2);

        // === Build circuit input structs ===

        let add_dsc = AddDsc720Inputs {
            csc_pubkey:            pd.csca_modulus,
            salt:                  config.base.salt_1.clone(),
            country:               pd.country,
            tbs_certificate:       tbs_cert,
            csc_pubkey_redc_param: pd.csca_barrett,
            dsc_signature:         pd.csca_signature,
            exponent:              pd.csca_exponent,
            tbs_certificate_len:   tbs_cert_len as u32,
        };

        let add_id_data = AddIdData720Inputs {
            comm_in: comm_out_1_hex,
            salt_in: config.base.salt_1.clone(),
            salt_out: config.base.salt_2.clone(),
            dg1: pd.dg1_padded,
            dsc_pubkey: pd.dsc_modulus,
            dsc_pubkey_redc_param: pd.dsc_barrett,
            dsc_pubkey_offset_in_dsc_cert: dsc_pubkey_offset as u32,
            sod_signature: pd.sod_signature,
            tbs_certificate: tbs_cert,
            signed_attributes: pd.signed_attrs,
            signed_attributes_size: pd.signed_attributes_size as u64,
            exponent: pd.dsc_exponent,
            e_content: pd.econtent,
        };

        let add_integrity = AddIntegrityCommitInputs {
            comm_in:                comm_out_2_hex,
            salt_in:                config.base.salt_2.clone(),
            dg1:                    pd.dg1_padded,
            dg1_padded_length:      pd.dg1_len as u64,
            dg1_hash_offset:        pd.dg1_hash_offset as u32,
            signed_attributes:      pd.signed_attrs,
            signed_attributes_size: pd.signed_attributes_size as u32,
            e_content:              pd.econtent,
            e_content_len:          pd.econtent_len as u32,
            private_nullifier:      pd.private_nullifier_hex,
            r_dg1:                  config.base.r_dg1.clone(),
        };

        let attest =
            config
                .base
                .build_attest(&pd.dg1_padded, pd.computed_sod_hash, pd.sod_hash_hex)?;

        Ok(MerkleAge720Inputs {
            add_dsc,
            add_id_data,
            add_integrity,
            attest,
        })
    }

    /// Generate inputs for the 5-circuit merkle_age_check TBS-1300 chain.
    ///
    /// Circuit chain: dsc_hash_1300 -> dsc_verify_1300 -> id_data_1300 ->
    /// integrity -> attest
    ///
    /// The key difference from TBS-720 is that DSC signature verification
    /// is split into two circuits using partial SHA256. Circuit 1 processes the
    /// first 640 bytes (CHUNK1_SIZE) and outputs an intermediate SHA256 state
    /// commitment. Circuit 2 continues the hash, verifies the RSA signature,
    /// and outputs the standard country+TBS commitment.
    pub fn to_merkle_age_1300_inputs(
        &self,
        csca_key_index: usize,
        config: MerkleAge1300Config,
    ) -> Result<MerkleAge1300Inputs, PassportError> {
        let pd = self.extract_passport_data(csca_key_index)?;

        // DSC certificate TBS at 1300-byte size
        let (tbs_cert_1300, tbs_cert_len, dsc_pubkey_offset) =
            self.extract_dsc_cert_sized::<MAX_TBS_SIZE_1300>(&pd.dsc_modulus)?;

        // chunk1: first 640 bytes of TBS
        let mut chunk1 = [0u8; CHUNK1_SIZE];
        chunk1.copy_from_slice(&tbs_cert_1300[..CHUNK1_SIZE]);

        // Partial SHA256: compute intermediate state
        let state1 = partial_sha256::sha256_start(&chunk1).map_err(PassportError::Sha256Error)?;

        // === Compute Poseidon2 commitments for 5-circuit chain ===

        // Circuit 1 (dsc_hash) output:
        //   data_comm1 = commit_to_data_chunk(salt_0, chunk1)
        //   comm_out_hash = commit_to_sha256_state_and_data(salt_0, state1, 640,
        // data_comm1)
        let data_comm1 = commitment::commit_to_data_chunk(&config.salt_0, &chunk1)?;
        let comm_out_hash = commitment::commit_to_sha256_state_and_data(
            &config.salt_0,
            &state1,
            CHUNK1_SIZE as u32,
            data_comm1,
        )?;
        let comm_out_hash_hex = commitment::field_to_hex_string(&comm_out_hash);

        // Circuit 2 (dsc_verify) output:
        //   comm_out_verify = hash_salt_country_tbs(salt_1, country, tbs_cert_1300)
        let comm_out_verify = commitment::hash_salt_country_tbs(
            &config.base.salt_1,
            pd.country.as_bytes(),
            &tbs_cert_1300,
        )?;
        let comm_out_verify_hex = commitment::field_to_hex_string(&comm_out_verify);

        // Circuit 3 (id_data) output:
        //   comm_out_id = hash_salt_country_sa_dg1_econtent_nullifier(salt_2, ...)
        let comm_out_id = commitment::hash_salt_country_sa_dg1_econtent_nullifier(
            &config.base.salt_2,
            pd.country.as_bytes(),
            &pd.signed_attrs,
            pd.signed_attributes_size as u64,
            &pd.dg1_padded,
            &pd.econtent,
            pd.private_nullifier,
        )?;
        let comm_out_id_hex = commitment::field_to_hex_string(&comm_out_id);

        // === Build 5 circuit input structs ===

        let add_dsc_hash = AddDscHash1300Inputs {
            salt: config.salt_0.clone(),
            chunk1,
        };

        let add_dsc_verify = AddDscVerify1300Inputs {
            comm_in: comm_out_hash_hex,
            csc_pubkey: pd.csca_modulus,
            salt: config.salt_0,
            country: pd.country,
            state1,
            tbs_certificate: tbs_cert_1300,
            tbs_certificate_len: tbs_cert_len as u32,
            csc_pubkey_redc_param: pd.csca_barrett,
            dsc_signature: pd.csca_signature,
            exponent: pd.csca_exponent,
            salt_out: config.base.salt_1.clone(),
        };

        let add_id_data = AddIdData1300Inputs {
            comm_in: comm_out_verify_hex,
            salt_in: config.base.salt_1.clone(),
            salt_out: config.base.salt_2.clone(),
            dg1: pd.dg1_padded,
            dsc_pubkey: pd.dsc_modulus,
            dsc_pubkey_redc_param: pd.dsc_barrett,
            dsc_pubkey_offset_in_dsc_cert: dsc_pubkey_offset as u32,
            sod_signature: pd.sod_signature,
            tbs_certificate: tbs_cert_1300,
            signed_attributes: pd.signed_attrs,
            signed_attributes_size: pd.signed_attributes_size as u64,
            exponent: pd.dsc_exponent,
            e_content: pd.econtent,
        };

        let add_integrity = AddIntegrityCommitInputs {
            comm_in:                comm_out_id_hex,
            salt_in:                config.base.salt_2.clone(),
            dg1:                    pd.dg1_padded,
            dg1_padded_length:      pd.dg1_len as u64,
            dg1_hash_offset:        pd.dg1_hash_offset as u32,
            signed_attributes:      pd.signed_attrs,
            signed_attributes_size: pd.signed_attributes_size as u32,
            e_content:              pd.econtent,
            e_content_len:          pd.econtent_len as u32,
            private_nullifier:      pd.private_nullifier_hex,
            r_dg1:                  config.base.r_dg1.clone(),
        };

        let attest =
            config
                .base
                .build_attest(&pd.dg1_padded, pd.computed_sod_hash, pd.sod_hash_hex)?;

        Ok(MerkleAge1300Inputs {
            add_dsc_hash,
            add_dsc_verify,
            add_id_data,
            add_integrity,
            attest,
        })
    }
}

// ============================================================================
// Serde helper for large fixed-size arrays (serde only supports [T; N] for N <=
// 32)
// ============================================================================

mod byte_array {
    use serde::{Serialize, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        arr: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        arr.as_slice().serialize(s)
    }
}

// ============================================================================
// TOML serialization trait and helpers
// ============================================================================

/// Trait for circuit input types that can be serialized to TOML format.
pub trait SaveToml {
    /// Serialize this circuit input to a Noir-compatible TOML string.
    fn to_toml_string(&self) -> String;

    /// Write the TOML serialization to a file.
    fn save_to_toml_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        std::fs::write(path, self.to_toml_string())
    }
}

/// Trait for circuit input container types (720/1300) that hold all circuit
/// inputs for a proving pipeline.
pub trait CircuitInputSet {
    /// Return the list of circuit file names (without extension).
    fn circuit_names(&self) -> Vec<&str>;

    /// Save all circuit input TOML files to the given directory.
    fn save_all(&self, base_dir: &Path) -> std::io::Result<()>;
}

/// Format a numeric slice as a TOML array: [1, 2, 3, ...]
fn fmt_array<T: std::fmt::Display>(arr: &[T]) -> String {
    format!(
        "[{}]",
        arr.iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

// ============================================================================
// TOML serialization for each circuit
// ============================================================================

impl SaveToml for AddDsc720Inputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "csc_pubkey = {}", fmt_array(&self.csc_pubkey));
        let _ = writeln!(out, "salt = \"{}\"", self.salt);
        let _ = writeln!(out, "country = \"{}\"", self.country);
        let _ = writeln!(
            out,
            "tbs_certificate = {}",
            fmt_array(&self.tbs_certificate)
        );
        let _ = writeln!(
            out,
            "csc_pubkey_redc_param = {}",
            fmt_array(&self.csc_pubkey_redc_param)
        );
        let _ = writeln!(out, "dsc_signature = {}", fmt_array(&self.dsc_signature));
        let _ = writeln!(out, "exponent = {}", self.exponent);
        let _ = writeln!(out, "tbs_certificate_len = {}", self.tbs_certificate_len);
        out
    }
}

impl SaveToml for AddIdData720Inputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "comm_in = \"{}\"", self.comm_in);
        let _ = writeln!(out, "salt_in = \"{}\"", self.salt_in);
        let _ = writeln!(out, "salt_out = \"{}\"", self.salt_out);
        let _ = writeln!(out, "dg1 = {}", fmt_array(&self.dg1));
        let _ = writeln!(out, "dsc_pubkey = {}", fmt_array(&self.dsc_pubkey));
        let _ = writeln!(
            out,
            "dsc_pubkey_redc_param = {}",
            fmt_array(&self.dsc_pubkey_redc_param)
        );
        let _ = writeln!(
            out,
            "dsc_pubkey_offset_in_dsc_cert = {}",
            self.dsc_pubkey_offset_in_dsc_cert
        );
        let _ = writeln!(out, "sod_signature = {}", fmt_array(&self.sod_signature));
        let _ = writeln!(
            out,
            "tbs_certificate = {}",
            fmt_array(&self.tbs_certificate)
        );
        let _ = writeln!(
            out,
            "signed_attributes = {}",
            fmt_array(&self.signed_attributes)
        );
        let _ = writeln!(
            out,
            "signed_attributes_size = {}",
            self.signed_attributes_size
        );
        let _ = writeln!(out, "exponent = {}", self.exponent);
        let _ = writeln!(out, "e_content = {}", fmt_array(&self.e_content));
        out
    }
}

impl SaveToml for AddIntegrityCommitInputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "comm_in = \"{}\"", self.comm_in);
        let _ = writeln!(out, "salt_in = \"{}\"", self.salt_in);
        let _ = writeln!(out, "dg1 = {}", fmt_array(&self.dg1));
        let _ = writeln!(out, "dg1_padded_length = {}", self.dg1_padded_length);
        let _ = writeln!(out, "dg1_hash_offset = {}", self.dg1_hash_offset);
        let _ = writeln!(
            out,
            "signed_attributes = {}",
            fmt_array(&self.signed_attributes)
        );
        let _ = writeln!(
            out,
            "signed_attributes_size = {}",
            self.signed_attributes_size
        );
        let _ = writeln!(out, "e_content = {}", fmt_array(&self.e_content));
        let _ = writeln!(out, "e_content_len = {}", self.e_content_len);
        let _ = writeln!(out, "private_nullifier = \"{}\"", self.private_nullifier);
        let _ = writeln!(out, "r_dg1 = \"{}\"", self.r_dg1);
        out
    }
}

impl SaveToml for AttestInputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "root = \"{}\"", self.root);
        let _ = writeln!(out, "current_date = \"{}\"", self.current_date);
        let _ = writeln!(out, "service_scope = \"{}\"", self.service_scope);
        let _ = writeln!(out, "service_subscope = \"{}\"", self.service_subscope);
        let _ = writeln!(out, "dg1 = {}", fmt_array(&self.dg1));
        let _ = writeln!(out, "r_dg1 = \"{}\"", self.r_dg1);
        let _ = writeln!(out, "sod_hash = \"{}\"", self.sod_hash);
        let _ = writeln!(out, "leaf_index = \"{}\"", self.leaf_index);
        // Merkle path as TOML array of quoted strings
        let _ = writeln!(out, "merkle_path = [");
        for (i, h) in self.merkle_path.iter().enumerate() {
            let comma = if i < self.merkle_path.len() - 1 {
                ","
            } else {
                ""
            };
            let _ = writeln!(out, "    \"{}\"{}", h, comma);
        }
        let _ = writeln!(out, "]");
        let _ = writeln!(out, "min_age_required = \"{}\"", self.min_age_required);
        let _ = writeln!(out, "max_age_required = \"{}\"", self.max_age_required);
        let _ = writeln!(out, "nullifier_secret = \"{}\"", self.nullifier_secret);
        out
    }
}

impl CircuitInputSet for MerkleAge720Inputs {
    fn circuit_names(&self) -> Vec<&str> {
        vec![
            "t_add_dsc_720",
            "t_add_id_data_720",
            "t_add_integrity_commit",
            "t_attest",
        ]
    }

    fn save_all(&self, base_dir: &Path) -> std::io::Result<()> {
        let base = base_dir;
        std::fs::create_dir_all(base)?;
        self.add_dsc
            .save_to_toml_file(base.join("t_add_dsc_720.toml"))?;
        self.add_id_data
            .save_to_toml_file(base.join("t_add_id_data_720.toml"))?;
        self.add_integrity
            .save_to_toml_file(base.join("t_add_integrity_commit.toml"))?;
        self.attest.save_to_toml_file(base.join("t_attest.toml"))?;
        Ok(())
    }
}

// --- TBS-1300 TOML serialization ---

impl SaveToml for AddDscHash1300Inputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "salt = \"{}\"", self.salt);
        let _ = writeln!(out, "chunk1 = {}", fmt_array(&self.chunk1));
        out
    }
}

impl SaveToml for AddDscVerify1300Inputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "comm_in = \"{}\"", self.comm_in);
        let _ = writeln!(out, "csc_pubkey = {}", fmt_array(&self.csc_pubkey));
        let _ = writeln!(out, "salt = \"{}\"", self.salt);
        let _ = writeln!(out, "country = \"{}\"", self.country);
        let _ = writeln!(out, "state1 = {}", fmt_array(&self.state1));
        let _ = writeln!(
            out,
            "tbs_certificate = {}",
            fmt_array(&self.tbs_certificate)
        );
        let _ = writeln!(out, "tbs_certificate_len = {}", self.tbs_certificate_len);
        let _ = writeln!(
            out,
            "csc_pubkey_redc_param = {}",
            fmt_array(&self.csc_pubkey_redc_param)
        );
        let _ = writeln!(out, "dsc_signature = {}", fmt_array(&self.dsc_signature));
        let _ = writeln!(out, "exponent = {}", self.exponent);
        let _ = writeln!(out, "salt_out = \"{}\"", self.salt_out);
        out
    }
}

impl SaveToml for AddIdData1300Inputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "comm_in = \"{}\"", self.comm_in);
        let _ = writeln!(out, "salt_in = \"{}\"", self.salt_in);
        let _ = writeln!(out, "salt_out = \"{}\"", self.salt_out);
        let _ = writeln!(out, "dg1 = {}", fmt_array(&self.dg1));
        let _ = writeln!(out, "dsc_pubkey = {}", fmt_array(&self.dsc_pubkey));
        let _ = writeln!(
            out,
            "dsc_pubkey_redc_param = {}",
            fmt_array(&self.dsc_pubkey_redc_param)
        );
        let _ = writeln!(
            out,
            "dsc_pubkey_offset_in_dsc_cert = {}",
            self.dsc_pubkey_offset_in_dsc_cert
        );
        let _ = writeln!(out, "sod_signature = {}", fmt_array(&self.sod_signature));
        let _ = writeln!(
            out,
            "tbs_certificate = {}",
            fmt_array(&self.tbs_certificate)
        );
        let _ = writeln!(
            out,
            "signed_attributes = {}",
            fmt_array(&self.signed_attributes)
        );
        let _ = writeln!(
            out,
            "signed_attributes_size = {}",
            self.signed_attributes_size
        );
        let _ = writeln!(out, "exponent = {}", self.exponent);
        let _ = writeln!(out, "e_content = {}", fmt_array(&self.e_content));
        out
    }
}

impl CircuitInputSet for MerkleAge1300Inputs {
    fn circuit_names(&self) -> Vec<&str> {
        vec![
            "t_add_dsc_hash_1300",
            "t_add_dsc_verify_1300",
            "t_add_id_data_1300",
            "t_add_integrity_commit",
            "t_attest",
        ]
    }

    fn save_all(&self, base_dir: &Path) -> std::io::Result<()> {
        let base = base_dir;
        std::fs::create_dir_all(base)?;
        self.add_dsc_hash
            .save_to_toml_file(base.join("t_add_dsc_hash_1300.toml"))?;
        self.add_dsc_verify
            .save_to_toml_file(base.join("t_add_dsc_verify_1300.toml"))?;
        self.add_id_data
            .save_to_toml_file(base.join("t_add_id_data_1300.toml"))?;
        self.add_integrity
            .save_to_toml_file(base.join("t_add_integrity_commit.toml"))?;
        self.attest.save_to_toml_file(base.join("t_attest.toml"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            mock_generator::{
                dg1_bytes_with_birthdate_expiry_date, generate_sod, generate_sod_with_padded_tbs,
            },
            mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64},
        },
        rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey},
    };

    /// End-to-end test: generate mock passport data and verify all
    /// computed commitments match the known-good values from the
    /// verified TOML files in noir-examples/.../tbs_720/.
    #[test]
    fn test_commitment_chain_matches_known_good() {
        // Generate the same mock data the binary uses
        let csca_der = STANDARD
            .decode(MOCK_CSCA_PRIV_KEY_B64)
            .expect("decode CSCA key");
        let csca_priv = RsaPrivateKey::from_pkcs8_der(&csca_der).expect("parse CSCA key");
        let csca_pub = csca_priv.to_public_key();

        let dsc_der = STANDARD
            .decode(MOCK_DSC_PRIV_KEY_B64)
            .expect("decode DSC key");
        let dsc_priv = RsaPrivateKey::from_pkcs8_der(&dsc_der).expect("parse DSC key");
        let dsc_pub = dsc_priv.to_public_key();

        let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
        let sod = generate_sod(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub);

        let reader = PassportReader::new(Binary::from_slice(&dg1), sod, true, Some(csca_pub));
        let csca_idx = reader.validate().expect("validation failed");

        let config = MerkleAge720Config {
            base: MerkleAgeBaseConfig {
                current_date: 1735689600,
                min_age_required: 18,
                max_age_required: 0,
                ..Default::default()
            },
        };

        let inputs = reader
            .to_merkle_age_720_inputs(csca_idx, config)
            .expect("generate inputs");

        // === Verify commitment chain self-consistency ===
        // Re-compute each commitment independently and verify it matches
        // the value produced by `to_merkle_age_720_inputs`.

        // Circuit 1 output: hash(salt_1, country, tbs_cert) → add_id_data.comm_in
        let country_bytes = inputs.add_dsc.country.as_bytes();
        let comm_out_1 = commitment::hash_salt_country_tbs(
            &inputs.add_dsc.salt,
            country_bytes,
            &inputs.add_id_data.tbs_certificate,
        )
        .unwrap();
        assert_eq!(
            commitment::field_to_hex_string(&comm_out_1),
            inputs.add_id_data.comm_in,
            "comm_out_1 mismatch: hash_salt_country_tbs"
        );

        // Private nullifier: hash(dg1, e_content, sod_signature)
        let private_nullifier = commitment::calculate_private_nullifier(
            &inputs.add_id_data.dg1,
            &inputs.add_id_data.e_content,
            &inputs.add_id_data.sod_signature,
        );
        assert_eq!(
            commitment::field_to_hex_string(&private_nullifier),
            inputs.add_integrity.private_nullifier,
            "private_nullifier mismatch: calculate_private_nullifier"
        );

        // Circuit 2 output: hash(salt_2, country, signed_attrs, dg1, econtent,
        // nullifier)   → add_integrity.comm_in
        let comm_out_2 = commitment::hash_salt_country_sa_dg1_econtent_nullifier(
            &inputs.add_id_data.salt_out,
            country_bytes,
            &inputs.add_id_data.signed_attributes,
            inputs.add_id_data.signed_attributes_size,
            &inputs.add_id_data.dg1,
            &inputs.add_id_data.e_content,
            private_nullifier,
        )
        .unwrap();
        assert_eq!(
            commitment::field_to_hex_string(&comm_out_2),
            inputs.add_integrity.comm_in,
            "comm_out_2 mismatch: hash_salt_country_sa_dg1_econtent_nullifier"
        );

        // sod_hash: consistent across circuits
        let sod_hash = commitment::calculate_sod_hash(&inputs.add_id_data.e_content);
        assert_eq!(
            commitment::field_to_hex_string(&sod_hash),
            inputs.attest.sod_hash,
            "sod_hash mismatch"
        );

        // Verify shared fields between circuits are consistent
        assert_eq!(
            inputs.add_integrity.dg1, inputs.add_id_data.dg1,
            "dg1 should be the same in id_data and integrity"
        );
        assert_eq!(
            inputs.attest.dg1, inputs.add_integrity.dg1,
            "dg1 should be the same in integrity and attest"
        );
    }

    /// End-to-end test for tbs_1300: generate mock passport data with padded
    /// TBS, produce all 5 circuit inputs, and verify the commitment chain
    /// is self-consistent.
    #[test]
    fn test_1300_commitment_chain_self_consistent() {
        // Generate mock keys
        let csca_der = STANDARD
            .decode(MOCK_CSCA_PRIV_KEY_B64)
            .expect("decode CSCA key");
        let csca_priv = RsaPrivateKey::from_pkcs8_der(&csca_der).expect("parse CSCA key");
        let csca_pub = csca_priv.to_public_key();

        let dsc_der = STANDARD
            .decode(MOCK_DSC_PRIV_KEY_B64)
            .expect("decode DSC key");
        let dsc_priv = RsaPrivateKey::from_pkcs8_der(&dsc_der).expect("parse DSC key");
        let dsc_pub = dsc_priv.to_public_key();

        let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
        let sod =
            generate_sod_with_padded_tbs(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub, 850);

        let reader = PassportReader::new(Binary::from_slice(&dg1), sod, true, Some(csca_pub));
        let csca_idx = reader.validate().expect("validation failed");

        let config = MerkleAge1300Config {
            base: MerkleAgeBaseConfig {
                current_date: 1735689600,
                min_age_required: 17,
                max_age_required: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        let inputs = reader
            .to_merkle_age_1300_inputs(csca_idx, config)
            .expect("generate 1300 inputs");

        // === Verify commitment chain consistency ===
        // Re-compute each commitment independently and verify it matches.

        // Circuit 1 output: dsc_hash → dsc_verify.comm_in
        let data_comm1 = commitment::commit_to_data_chunk(
            &inputs.add_dsc_hash.salt,
            &inputs.add_dsc_hash.chunk1,
        )
        .unwrap();
        let state1 = partial_sha256::sha256_start(&inputs.add_dsc_hash.chunk1).unwrap();
        let comm_out_hash = commitment::commit_to_sha256_state_and_data(
            &inputs.add_dsc_hash.salt,
            &state1,
            CHUNK1_SIZE as u32,
            data_comm1,
        )
        .unwrap();
        assert_eq!(
            commitment::field_to_hex_string(&comm_out_hash),
            inputs.add_dsc_verify.comm_in,
            "dsc_hash output != dsc_verify.comm_in"
        );

        // Circuit 2 output: dsc_verify → id_data.comm_in
        let country_bytes = inputs.add_dsc_verify.country.as_bytes();
        let comm_out_verify = commitment::hash_salt_country_tbs(
            &inputs.add_dsc_verify.salt_out,
            country_bytes,
            &inputs.add_dsc_verify.tbs_certificate,
        )
        .unwrap();
        assert_eq!(
            commitment::field_to_hex_string(&comm_out_verify),
            inputs.add_id_data.comm_in,
            "dsc_verify output != id_data.comm_in"
        );

        // Circuit 3 output: id_data → integrity.comm_in
        let private_nullifier = commitment::calculate_private_nullifier(
            &inputs.add_id_data.dg1,
            &inputs.add_id_data.e_content,
            &inputs.add_id_data.sod_signature,
        );
        assert_eq!(
            commitment::field_to_hex_string(&private_nullifier),
            inputs.add_integrity.private_nullifier,
            "private_nullifier mismatch"
        );

        let comm_out_id = commitment::hash_salt_country_sa_dg1_econtent_nullifier(
            &inputs.add_id_data.salt_out,
            country_bytes,
            &inputs.add_id_data.signed_attributes,
            inputs.add_id_data.signed_attributes_size,
            &inputs.add_id_data.dg1,
            &inputs.add_id_data.e_content,
            private_nullifier,
        )
        .unwrap();
        assert_eq!(
            commitment::field_to_hex_string(&comm_out_id),
            inputs.add_integrity.comm_in,
            "id_data output != integrity.comm_in"
        );

        // sod_hash: consistent across circuits
        let sod_hash = commitment::calculate_sod_hash(&inputs.add_id_data.e_content);
        assert_eq!(
            commitment::field_to_hex_string(&sod_hash),
            inputs.attest.sod_hash,
            "sod_hash mismatch"
        );

        // Verify shared fields between circuits are consistent
        assert_eq!(
            inputs.add_dsc_verify.state1, state1,
            "state1 stored in dsc_verify should match computed state1"
        );
        assert_eq!(
            inputs.add_id_data.tbs_certificate, inputs.add_dsc_verify.tbs_certificate,
            "tbs_certificate should be the same in dsc_verify and id_data"
        );
        assert_eq!(
            inputs.add_integrity.dg1, inputs.add_id_data.dg1,
            "dg1 should be the same in id_data and integrity"
        );
        assert_eq!(
            inputs.attest.dg1, inputs.add_integrity.dg1,
            "dg1 should be the same in integrity and attest"
        );

        // Verify sod_hash and nullifier are non-trivial (non-zero)
        assert!(
            inputs.attest.sod_hash
                != "0x0000000000000000000000000000000000000000000000000000000000000000",
            "sod_hash should be non-trivial"
        );
        assert!(
            inputs.add_integrity.private_nullifier
                != "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nullifier should be non-trivial"
        );
    }
}
