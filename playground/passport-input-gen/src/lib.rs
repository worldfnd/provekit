pub mod commitment;
pub mod mock_generator;
pub mod mock_keys;
pub mod parser;
pub mod poseidon2;

pub use crate::parser::{binary::Binary, sod::SOD};
use {
    crate::parser::{
        types::{
            DigestAlgorithm, PassportError, RsaKeyBits, RsaPadding, SignatureAlgorithmName,
            MAX_DG1_SIZE, MAX_ECONTENT_SIZE, MAX_SIGNED_ATTRIBUTES_SIZE, TBS_SIZES, TREE_DEPTH,
        },
        utils::{fit, load_csca_public_keys, to_u32, ASN1_HEADER_LEN, ASN1_OCTET_STRING_TAG},
    },
    base64::{engine::general_purpose::STANDARD, Engine as _},
    noir_bignum_paramgen::compute_barrett_reduction_parameter,
    rsa::{
        pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts, BigUint,
        Pkcs1v15Sign, Pss, RsaPublicKey,
    },
    sha1::Sha1,
    sha2::{Digest, Sha224, Sha256, Sha384, Sha512},
    std::{fmt::Write as _, path::Path},
};

// ============================================================================
// Constants
// ============================================================================

/// Zero BN254 field element as a 0x-prefixed hex string.
pub const ZERO_FIELD: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// Determine the effective DG1 length, mirroring the Noir circuit's
/// `get_dg1_size` / `is_id_card` logic.  Passports use 93 bytes; ID cards
/// use the full 95 bytes.  The distinction is that ID-card DG1 data has
/// non-zero bytes at positions 93 and 94.
pub fn effective_dg1_len(dg1: &[u8]) -> usize {
    if dg1.len() >= 95 && dg1[93] != 0 && dg1[94] != 0 {
        95
    } else {
        93
    }
}

// ============================================================================
// Hash dispatch helpers
// ============================================================================

/// Hash `data` using the specified digest algorithm.
fn hash_bytes(algo: &DigestAlgorithm, data: &[u8]) -> Vec<u8> {
    match algo {
        DigestAlgorithm::SHA1 => Sha1::digest(data).to_vec(),
        DigestAlgorithm::SHA224 => Sha224::digest(data).to_vec(),
        DigestAlgorithm::SHA256 => Sha256::digest(data).to_vec(),
        DigestAlgorithm::SHA384 => Sha384::digest(data).to_vec(),
        DigestAlgorithm::SHA512 => Sha512::digest(data).to_vec(),
    }
}

/// Extract the digest algorithm implied by an RSA signature algorithm OID name.
/// Returns `None` for algorithm-agnostic OIDs (plain `RsaEncryption`,
/// `RsassaPss`).
fn digest_from_sig_algo_name(name: &SignatureAlgorithmName) -> Option<DigestAlgorithm> {
    match name {
        SignatureAlgorithmName::Sha1WithRsaSignature => Some(DigestAlgorithm::SHA1),
        SignatureAlgorithmName::Sha256WithRsaEncryption => Some(DigestAlgorithm::SHA256),
        SignatureAlgorithmName::Sha384WithRsaEncryption => Some(DigestAlgorithm::SHA384),
        SignatureAlgorithmName::Sha512WithRsaEncryption => Some(DigestAlgorithm::SHA512),
        _ => None,
    }
}

/// Verify an RSA PKCS#1 v1.5 signature with the given digest algorithm.
fn rsa_verify_pkcs1(
    key: &RsaPublicKey,
    digest: &[u8],
    sig: &[u8],
    algo: &DigestAlgorithm,
) -> rsa::Result<()> {
    match algo {
        DigestAlgorithm::SHA1 => key.verify(Pkcs1v15Sign::new::<Sha1>(), digest, sig),
        DigestAlgorithm::SHA224 => key.verify(Pkcs1v15Sign::new::<Sha224>(), digest, sig),
        DigestAlgorithm::SHA256 => key.verify(Pkcs1v15Sign::new::<Sha256>(), digest, sig),
        DigestAlgorithm::SHA384 => key.verify(Pkcs1v15Sign::new::<Sha384>(), digest, sig),
        DigestAlgorithm::SHA512 => key.verify(Pkcs1v15Sign::new::<Sha512>(), digest, sig),
    }
}

/// Verify an RSA-PSS signature with the given digest algorithm.
fn rsa_verify_pss(
    key: &RsaPublicKey,
    digest: &[u8],
    sig: &[u8],
    algo: &DigestAlgorithm,
) -> rsa::Result<()> {
    match algo {
        DigestAlgorithm::SHA1 => key.verify(Pss::new::<Sha1>(), digest, sig),
        DigestAlgorithm::SHA224 => key.verify(Pss::new::<Sha224>(), digest, sig),
        DigestAlgorithm::SHA256 => key.verify(Pss::new::<Sha256>(), digest, sig),
        DigestAlgorithm::SHA384 => key.verify(Pss::new::<Sha384>(), digest, sig),
        DigestAlgorithm::SHA512 => key.verify(Pss::new::<Sha512>(), digest, sig),
    }
}

// ============================================================================
// Helpers for variable-size byte arrays
// ============================================================================

/// Left-pad `data` with zeros to `target` bytes (big-endian number padding).
fn fit_vec_leading(data: &[u8], target: usize, name: &str) -> Result<Vec<u8>, PassportError> {
    if data.len() > target {
        return Err(PassportError::BufferOverflow(format!(
            "{}: {} bytes > {} target",
            name,
            data.len(),
            target
        )));
    }
    let mut padded = vec![0u8; target];
    padded[target - data.len()..].copy_from_slice(data);
    Ok(padded)
}

/// Right-pad `data` with zeros to `target` bytes (data buffer padding).
fn fit_vec_trailing(data: &[u8], target: usize, name: &str) -> Result<Vec<u8>, PassportError> {
    if data.len() > target {
        return Err(PassportError::BufferOverflow(format!(
            "{}: {} bytes > {} target",
            name,
            data.len(),
            target
        )));
    }
    let mut padded = vec![0u8; target];
    padded[..data.len()].copy_from_slice(data);
    Ok(padded)
}

// ============================================================================
// Circuit Variant Configuration
// ============================================================================

/// Describes which specific circuit variants to generate inputs for.
#[derive(Debug, Clone)]
pub struct CircuitVariant {
    /// TBS certificate max size (700, 1000, 1200, 1600)
    pub tbs_size:      usize,
    /// CSCA RSA key size
    pub csca_key_bits: RsaKeyBits,
    /// DSC RSA key size
    pub dsc_key_bits:  RsaKeyBits,
    /// RSA padding scheme for CSCA→DSC signature
    pub csca_padding:  RsaPadding,
    /// RSA padding scheme for DSC→SOD signature
    pub dsc_padding:   RsaPadding,
    /// Hash algorithm for signed_attributes digest
    pub sa_hash:       DigestAlgorithm,
    /// Hash algorithm for DG1 digest in eContent
    pub dg_hash:       DigestAlgorithm,
}

impl Default for CircuitVariant {
    fn default() -> Self {
        Self {
            tbs_size:      700,
            csca_key_bits: RsaKeyBits::Rsa4096,
            dsc_key_bits:  RsaKeyBits::Rsa2048,
            csca_padding:  RsaPadding::Pkcs1,
            dsc_padding:   RsaPadding::Pkcs1,
            sa_hash:       DigestAlgorithm::SHA256,
            dg_hash:       DigestAlgorithm::SHA256,
        }
    }
}

impl CircuitVariant {
    pub fn validate(&self) -> Result<(), PassportError> {
        if !TBS_SIZES.contains(&self.tbs_size) {
            return Err(PassportError::DataNotFound(format!(
                "Unsupported TBS size: {}. Supported: {:?}",
                self.tbs_size, TBS_SIZES
            )));
        }
        Ok(())
    }

    /// Build circuit directory paths for each of the 4 stages.
    pub fn circuit_paths(&self) -> [String; 4] {
        let csca_key = self.csca_key_bits.bit_len();
        let dsc_key = self.dsc_key_bits.bit_len();
        let csca_pad = self.csca_padding.circuit_path();
        let dsc_pad = self.dsc_padding.circuit_path();
        let sa_hash = self.sa_hash.circuit_path();
        let dg_hash = self.dg_hash.circuit_path();

        [
            format!(
                "sig_check/dsc/tbs_{}/rsa/{}/{}/{}",
                self.tbs_size, csca_pad, csca_key, sa_hash
            ),
            format!(
                "sig_check/id_data/tbs_{}/rsa/{}/{}/{}",
                self.tbs_size, dsc_pad, dsc_key, sa_hash
            ),
            format!("data_check/integrity/sa_{}/dg_{}", sa_hash, dg_hash),
            "merkle_attest/age/standard".to_string(),
        ]
    }

    /// Human-readable circuit names (paths with `/` replaced by `_`).
    pub fn circuit_names(&self) -> [String; 4] {
        self.circuit_paths().map(|p| p.replace('/', "_"))
    }
}

// ============================================================================
// Attestation Configuration
// ============================================================================

/// Shared application-level parameters for the passport circuit pipeline.
pub struct AttestConfig {
    /// Salt for Stage 1 → Stage 2 commitment chain
    pub salt_1:           String,
    /// Salt for Stage 2 → Stage 3 commitment chain
    pub salt_2:           String,
    /// Blinding factor for DG1 Poseidon2 commitment (Merkle leaf privacy)
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
    /// Merkle tree root (from sequencer). Set to ZERO_FIELD to auto-compute.
    pub merkle_root:      String,
    /// Leaf index in Merkle tree
    pub leaf_index:       String,
    /// Merkle path sibling hashes (TREE_DEPTH elements)
    pub merkle_path:      Vec<String>,
}

impl Default for AttestConfig {
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

// ============================================================================
// Circuit input structs (4-stage pipeline)
// ============================================================================

/// Stage 1: sig-check/dsc — CSCA→DSC signature verification
#[derive(serde::Serialize)]
pub struct DscSigCheckInputs {
    pub salt:                  String,
    pub country:               String,
    pub tbs_certificate:       Vec<u8>,
    pub csc_pubkey:            Vec<u8>,
    pub csc_pubkey_redc_param: Vec<u8>,
    pub dsc_signature:         Vec<u8>,
    pub exponent:              u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pss_salt_len:          Option<u32>,
}

/// Stage 2: sig-check/id-data — DSC→SOD signature verification
#[derive(serde::Serialize)]
pub struct IdDataSigCheckInputs {
    pub comm_in:               String,
    pub salt_in:               String,
    pub salt_out:              String,
    pub dg1:                   Vec<u8>,
    pub dsc_pubkey:            Vec<u8>,
    pub dsc_pubkey_redc_param: Vec<u8>,
    pub sod_signature:         Vec<u8>,
    pub tbs_certificate:       Vec<u8>,
    pub signed_attributes:     Vec<u8>,
    pub exponent:              u32,
    pub e_content:             Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pss_salt_len:          Option<u32>,
}

/// Noir SaltedValue<[u8; N]> — nested struct for ABI-compatible JSON output.
#[derive(serde::Serialize)]
pub struct SaltedByteArray {
    pub salt:  String,
    pub value: Vec<u8>,
    pub hash:  String,
}

/// Noir SaltedValue<Field> — nested struct for ABI-compatible JSON output.
#[derive(serde::Serialize)]
pub struct SaltedFieldValue {
    pub salt:  String,
    pub value: String,
    pub hash:  String,
}

/// Stage 3: data-check/integrity — DG1 integrity + Merkle leaf
#[derive(serde::Serialize)]
pub struct IntegrityInputs {
    pub comm_in:                  String,
    pub salt_in:                  String,
    pub salted_dg1:               SaltedByteArray,
    pub r_dg1:                    String,
    pub signed_attributes:        Vec<u8>,
    pub e_content:                Vec<u8>,
    pub salted_private_nullifier: SaltedFieldValue,
}

/// Stage 4: merkle-attest/age/standard — Age attestation with Merkle proof
#[derive(serde::Serialize)]
pub struct AttestInputs {
    pub root:              String,
    pub current_date:      u64,
    pub min_age_required:  u8,
    pub max_age_required:  u8,
    pub service_scope:     String,
    pub service_subscope:  String,
    pub dg1:               Vec<u8>,
    pub e_content:         Vec<u8>,
    pub r_dg1:             String,
    pub private_nullifier: String,
    pub nullifier_secret:  String,
    pub leaf_index:        String,
    pub merkle_path:       Vec<String>,
}

/// Container for all 4 circuit inputs in the passport pipeline.
pub struct PassportCircuitInputs {
    pub variant:           CircuitVariant,
    pub dsc_sig_check:     DscSigCheckInputs,
    pub id_data_sig_check: IdDataSigCheckInputs,
    pub integrity:         IntegrityInputs,
    pub attest:            AttestInputs,
}

// ============================================================================
// Extracted passport data (internal)
// ============================================================================

struct PassportData {
    dg1_padded:             Vec<u8>,
    signed_attrs:           Vec<u8>,
    signed_attributes_size: usize,
    econtent:               Vec<u8>,
    dsc_modulus:            Vec<u8>,
    dsc_exponent:           u32,
    dsc_barrett:            Vec<u8>,
    sod_signature:          Vec<u8>,
    csca_modulus:           Vec<u8>,
    csca_exponent:          u32,
    csca_barrett:           Vec<u8>,
    csca_signature:         Vec<u8>,
    country:                String,
    private_nullifier:      ark_bn254::Fr,
    private_nullifier_hex:  String,
    computed_sod_hash:      ark_bn254::Fr,
}

// ============================================================================
// PassportReader
// ============================================================================

/// Parsed passport data
pub struct PassportReader {
    dg1:         Binary,
    sod:         SOD,
    mockdata:    bool,
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

    /// Extract SignedAttributes (padded + actual size)
    fn extract_signed_attrs(
        &self,
    ) -> Result<([u8; MAX_SIGNED_ATTRIBUTES_SIZE], usize), PassportError> {
        let signed_attrs = self.sod.signer_info.signed_attrs.bytes.as_bytes();
        let size = signed_attrs.len();
        let padded = fit::<MAX_SIGNED_ATTRIBUTES_SIZE>(signed_attrs)?;
        Ok((padded, size))
    }

    /// Extract eContent (padded + raw bytes)
    fn extract_econtent(&self) -> Result<([u8; MAX_ECONTENT_SIZE], &[u8]), PassportError> {
        let econtent_bytes = self.sod.encap_content_info.e_content.bytes.as_bytes();
        let padded = fit::<MAX_ECONTENT_SIZE>(econtent_bytes)?;
        Ok((padded, econtent_bytes))
    }

    /// Extract RSA key data (modulus, exponent, Barrett param, signature) as
    /// Vec<u8>.
    fn extract_rsa_key_data(
        pubkey: &RsaPublicKey,
        signature: &[u8],
        expected_key_bytes: usize,
        name: &str,
    ) -> Result<(Vec<u8>, u32, Vec<u8>, Vec<u8>), PassportError> {
        let modulus = fit_vec_leading(
            &pubkey.n().to_bytes_be(),
            expected_key_bytes,
            &format!("{} modulus", name),
        )?;
        let exponent = to_u32(pubkey.e().to_bytes_be())?;
        let barrett_raw =
            compute_barrett_reduction_parameter(&BigUint::from_bytes_be(&modulus)).to_bytes_be();
        let barrett = fit_vec_leading(
            &barrett_raw,
            expected_key_bytes + 1,
            &format!("{} Barrett", name),
        )?;
        let sig = fit_vec_leading(
            signature,
            expected_key_bytes,
            &format!("{} signature", name),
        )?;
        Ok((modulus, exponent, barrett, sig))
    }

    /// Extract DSC public key, exponent, Barrett mu, and SOD signature
    fn extract_dsc(
        &self,
        dsc_key_bytes: usize,
    ) -> Result<(Vec<u8>, u32, Vec<u8>, Vec<u8>), PassportError> {
        let der = self
            .sod
            .certificate
            .tbs
            .subject_public_key_info
            .subject_public_key
            .as_bytes();
        let pubkey =
            RsaPublicKey::from_pkcs1_der(der).map_err(|_| PassportError::DscPublicKeyInvalid)?;
        let signature = self.sod.signer_info.signature.as_bytes();
        Self::extract_rsa_key_data(&pubkey, signature, dsc_key_bytes, "DSC")
    }

    /// Decode a base64-encoded CSCA public key from DER format
    fn decode_csca_pubkey(b64: &str) -> Result<RsaPublicKey, PassportError> {
        let der = STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| PassportError::Base64DecodingFailed(e.to_string()))?;
        RsaPublicKey::from_public_key_der(&der).map_err(|_| PassportError::CscaPublicKeyInvalid)
    }

    /// Extract CSCA key data from a public key
    fn extract_csca_fields(
        &self,
        pubkey: &RsaPublicKey,
        csca_key_bytes: usize,
    ) -> Result<(Vec<u8>, u32, Vec<u8>, Vec<u8>), PassportError> {
        let signature = self.sod.certificate.signature.as_bytes();
        Self::extract_rsa_key_data(pubkey, signature, csca_key_bytes, "CSCA")
    }

    /// Extract CSCA data from the registry by country+index
    fn extract_csca(
        &self,
        idx: usize,
        csca_key_bytes: usize,
    ) -> Result<(Vec<u8>, u32, Vec<u8>, Vec<u8>), PassportError> {
        let csca_keys = load_csca_public_keys().map_err(|_| PassportError::FailedToLoadCscaKeys)?;
        let usa_csca = csca_keys.get("USA").ok_or(PassportError::NoUsaCsca)?;
        let pubkey = Self::decode_csca_pubkey(&usa_csca[idx].public_key)?;
        self.extract_csca_fields(&pubkey, csca_key_bytes)
    }

    /// Extract DSC certificate TBS padded to tbs_size
    fn extract_dsc_cert_padded(&self, tbs_size: usize) -> Result<(Vec<u8>, usize), PassportError> {
        let tbs_bytes = self.sod.certificate.tbs.bytes.as_bytes();
        let cert_len = tbs_bytes.len();
        let padded = fit_vec_trailing(tbs_bytes, tbs_size, "TBS certificate")?;
        Ok((padded, cert_len))
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

    /// Validate DG1, eContent, and signatures against DSC + CSCA.
    ///
    /// Hash algorithms are read from the SOD rather than hardcoded, so this
    /// works for SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 variants.
    pub fn validate(&self) -> Result<usize, PassportError> {
        let dg_hash = &self.sod.encap_content_info.e_content.hash_algorithm;
        let sa_hash = &self.sod.signer_info.digest_algorithm;

        // 1. Check DG1 hash inside eContent (uses dg_hash)
        let dg1_len = effective_dg1_len(self.dg1.as_bytes());
        let dg1_hash = hash_bytes(dg_hash, &self.dg1.as_bytes()[..dg1_len]);
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

        // 2. Check hash(eContent) inside SignedAttributes (uses sa_hash)
        let econtent_hash = hash_bytes(
            sa_hash,
            self.sod.encap_content_info.e_content.bytes.as_bytes(),
        );
        let mut msg_digest = self.sod.signer_info.signed_attrs.message_digest.as_bytes();

        if msg_digest.len() > ASN1_HEADER_LEN && msg_digest[0] == ASN1_OCTET_STRING_TAG {
            msg_digest = &msg_digest[ASN1_HEADER_LEN..];
        }

        if econtent_hash.as_slice() != msg_digest {
            return Err(PassportError::EcontentHashMismatch);
        }

        // 3. Verify SignedAttributes signature with DSC (uses sa_hash)
        let signed_attr_hash =
            hash_bytes(sa_hash, self.sod.signer_info.signed_attrs.bytes.as_bytes());
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
            SignatureAlgorithmName::Sha1WithRsaSignature
            | SignatureAlgorithmName::Sha256WithRsaEncryption
            | SignatureAlgorithmName::Sha384WithRsaEncryption
            | SignatureAlgorithmName::Sha512WithRsaEncryption
            | SignatureAlgorithmName::RsaEncryption => {
                rsa_verify_pkcs1(&dsc_pubkey, &signed_attr_hash, dsc_signature, sa_hash)
            }
            SignatureAlgorithmName::RsassaPss => {
                rsa_verify_pss(&dsc_pubkey, &signed_attr_hash, dsc_signature, sa_hash)
            }
            unsupported => {
                return Err(PassportError::UnsupportedSignatureAlgorithm(format!(
                    "{:?}",
                    unsupported
                )))
            }
        };
        verify_result.map_err(|_| PassportError::DscSignatureInvalid)?;

        // 4. Verify DSC certificate signature with CSCA.
        // The hash for TBS verification is derived from the certificate's
        // outer signature algorithm; fall back to sa_hash when the OID is
        // algorithm-agnostic (e.g. plain RsaEncryption or RSASSA-PSS).
        let cert_sig_name = &self.sod.certificate.signature_algorithm.name;
        let cert_hash = digest_from_sig_algo_name(cert_sig_name).unwrap_or(sa_hash.clone());

        let tbs_bytes = self.sod.certificate.tbs.bytes.as_bytes();
        let tbs_digest = hash_bytes(&cert_hash, tbs_bytes);
        let csca_signature = self.sod.certificate.signature.as_bytes();

        let verify_csca = |key: &RsaPublicKey| -> rsa::Result<()> {
            match cert_sig_name {
                SignatureAlgorithmName::RsassaPss => {
                    rsa_verify_pss(key, &tbs_digest, csca_signature, &cert_hash)
                }
                _ => rsa_verify_pkcs1(key, &tbs_digest, csca_signature, &cert_hash),
            }
        };

        if let Some(key) = &self.csca_pubkey {
            verify_csca(key).map_err(|_| PassportError::CscaSignatureInvalid)?;
            return Ok(0);
        }

        let all_csca = load_csca_public_keys().map_err(|_| PassportError::CscaKeysMissing)?;
        let usa_csca = all_csca.get("USA").ok_or(PassportError::NoUsaCsca)?;

        for (i, csca) in usa_csca.iter().enumerate() {
            let csca_pubkey = Self::decode_csca_pubkey(&csca.public_key)?;
            if verify_csca(&csca_pubkey).is_ok() {
                return Ok(i);
            }
        }
        Err(PassportError::CscaSignatureInvalid)
    }

    /// Extract all common passport data fields needed by the circuit pipeline.
    fn extract_passport_data(
        &self,
        csca_key_index: usize,
        variant: &CircuitVariant,
    ) -> Result<PassportData, PassportError> {
        let dg1_padded = fit::<MAX_DG1_SIZE>(self.dg1.as_bytes())?.to_vec();
        let (signed_attrs_arr, signed_attributes_size) = self.extract_signed_attrs()?;
        let signed_attrs = signed_attrs_arr.to_vec();
        let (econtent_arr, _econtent_bytes) = self.extract_econtent()?;
        let econtent = econtent_arr.to_vec();

        let dsc_key_bytes = variant.dsc_key_bits.byte_len();
        let csca_key_bytes = variant.csca_key_bits.byte_len();

        let (dsc_modulus, dsc_exponent, dsc_barrett, sod_signature) =
            self.extract_dsc(dsc_key_bytes)?;

        let (csca_modulus, csca_exponent, csca_barrett, csca_signature) = if self.mockdata {
            let key = self
                .csca_pubkey
                .as_ref()
                .ok_or(PassportError::MissingCscaMockKey)?;
            self.extract_csca_fields(key, csca_key_bytes)?
        } else {
            self.extract_csca(csca_key_index, csca_key_bytes)?
        };

        let country = self.extract_country();

        // Private nullifier: Poseidon2(packed_dg1, packed_e_content, packed_sod_sig)
        let private_nullifier =
            commitment::calculate_private_nullifier(&dg1_padded, &econtent, &sod_signature);
        let private_nullifier_hex = commitment::field_to_hex_string(&private_nullifier);

        let computed_sod_hash = commitment::calculate_sod_hash(&econtent);

        Ok(PassportData {
            dg1_padded,
            signed_attrs,
            signed_attributes_size,
            econtent,
            dsc_modulus,
            dsc_exponent,
            dsc_barrett,
            sod_signature,
            csca_modulus,
            csca_exponent,
            csca_barrett,
            csca_signature,
            country,
            private_nullifier,
            private_nullifier_hex,
            computed_sod_hash,
        })
    }

    /// Generate inputs for the 4-circuit passport pipeline.
    pub fn to_passport_inputs(
        &self,
        csca_key_index: usize,
        variant: &CircuitVariant,
        config: AttestConfig,
    ) -> Result<PassportCircuitInputs, PassportError> {
        variant.validate()?;
        let pd = self.extract_passport_data(csca_key_index, variant)?;

        // DSC certificate TBS padded to variant.tbs_size
        let (tbs_cert, _tbs_cert_len) = self.extract_dsc_cert_padded(variant.tbs_size)?;

        // === Compute Poseidon2 commitments ===

        // Stage 1 output: hash(salt_1, country, tbs_cert)
        let comm_out_1 =
            commitment::hash_salt_country_tbs(&config.salt_1, pd.country.as_bytes(), &tbs_cert)?;
        let comm_out_1_hex = commitment::field_to_hex_string(&comm_out_1);

        // Stage 2 output: hash(salt_2, country, signed_attr, sa_size, dg1, e_content,
        // nullifier)
        let comm_out_2 = commitment::hash_salt_country_sa_dg1_econtent_nullifier(
            &config.salt_2,
            pd.country.as_bytes(),
            &pd.signed_attrs,
            pd.signed_attributes_size as u64,
            &pd.dg1_padded,
            &pd.econtent,
            pd.private_nullifier,
        )?;
        let comm_out_2_hex = commitment::field_to_hex_string(&comm_out_2);

        // Merkle root: auto-compute if sentinel zero value
        let merkle_root = {
            if config.merkle_root == ZERO_FIELD {
                let h_dg1 = commitment::calculate_h_dg1(&config.r_dg1, &pd.dg1_padded)?;
                let leaf = commitment::calculate_leaf(h_dg1, pd.computed_sod_hash);
                let leaf_idx: u64 =
                    config
                        .leaf_index
                        .parse()
                        .map_err(|_| PassportError::InvalidLeafIndex {
                            value: config.leaf_index.clone(),
                        })?;
                let path_fields: Vec<ark_bn254::Fr> = config
                    .merkle_path
                    .iter()
                    .map(|s| commitment::parse_hex_to_field(s))
                    .collect::<Result<Vec<_>, _>>()?;
                let root = commitment::compute_merkle_root(leaf, leaf_idx, &path_fields);
                commitment::field_to_hex_string(&root)
            } else {
                config.merkle_root.clone()
            }
        };

        // === Build circuit input structs ===

        let csca_pss_salt = match variant.csca_padding {
            RsaPadding::Pss => Some(variant.sa_hash.hash_output_len()),
            RsaPadding::Pkcs1 => None,
        };

        let dsc_pss_salt = match variant.dsc_padding {
            RsaPadding::Pss => Some(variant.sa_hash.hash_output_len()),
            RsaPadding::Pkcs1 => None,
        };

        let dsc_sig_check = DscSigCheckInputs {
            salt:                  config.salt_1.clone(),
            country:               pd.country.clone(),
            tbs_certificate:       tbs_cert.clone(),
            csc_pubkey:            pd.csca_modulus,
            csc_pubkey_redc_param: pd.csca_barrett,
            dsc_signature:         pd.csca_signature,
            exponent:              pd.csca_exponent,
            pss_salt_len:          csca_pss_salt,
        };

        let id_data_sig_check = IdDataSigCheckInputs {
            comm_in:               comm_out_1_hex,
            salt_in:               config.salt_1.clone(),
            salt_out:              config.salt_2.clone(),
            dg1:                   pd.dg1_padded.clone(),
            dsc_pubkey:            pd.dsc_modulus,
            dsc_pubkey_redc_param: pd.dsc_barrett,
            sod_signature:         pd.sod_signature,
            tbs_certificate:       tbs_cert,
            signed_attributes:     pd.signed_attrs.clone(),
            exponent:              pd.dsc_exponent,
            e_content:             pd.econtent.clone(),
            pss_salt_len:          dsc_pss_salt,
        };

        let integrity = IntegrityInputs {
            comm_in:                  comm_out_2_hex,
            salt_in:                  config.salt_2.clone(),
            salted_dg1:               SaltedByteArray {
                salt:  "0x1".to_string(),
                value: pd.dg1_padded.clone(),
                hash:  "0x0".to_string(),
            },
            r_dg1:                    config.r_dg1.clone(),
            signed_attributes:        pd.signed_attrs,
            e_content:                pd.econtent.clone(),
            salted_private_nullifier: SaltedFieldValue {
                salt:  "0x1".to_string(),
                value: pd.private_nullifier_hex.clone(),
                hash:  "0x0".to_string(),
            },
        };

        let attest = AttestInputs {
            root:              merkle_root,
            current_date:      config.current_date,
            min_age_required:  config.min_age_required,
            max_age_required:  config.max_age_required,
            service_scope:     config.service_scope,
            service_subscope:  config.service_subscope,
            dg1:               pd.dg1_padded,
            e_content:         pd.econtent,
            r_dg1:             config.r_dg1,
            private_nullifier: pd.private_nullifier_hex,
            nullifier_secret:  config.nullifier_secret,
            leaf_index:        config.leaf_index,
            merkle_path:       config.merkle_path,
        };

        Ok(PassportCircuitInputs {
            variant: variant.clone(),
            dsc_sig_check,
            id_data_sig_check,
            integrity,
            attest,
        })
    }
}

// ============================================================================
// TOML serialization
// ============================================================================

/// Trait for circuit input types that can be serialized to TOML format.
pub trait SaveToml {
    fn to_toml_string(&self) -> String;

    fn save_to_toml_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        std::fs::write(path, self.to_toml_string())
    }
}

/// Trait for circuit input container types that hold all circuit inputs.
pub trait CircuitInputSet {
    fn circuit_names(&self) -> Vec<String>;
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

impl SaveToml for DscSigCheckInputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "salt = \"{}\"", self.salt);
        let _ = writeln!(out, "country = \"{}\"", self.country);
        let _ = writeln!(
            out,
            "tbs_certificate = {}",
            fmt_array(&self.tbs_certificate)
        );
        let _ = writeln!(out, "csc_pubkey = {}", fmt_array(&self.csc_pubkey));
        let _ = writeln!(
            out,
            "csc_pubkey_redc_param = {}",
            fmt_array(&self.csc_pubkey_redc_param)
        );
        let _ = writeln!(out, "dsc_signature = {}", fmt_array(&self.dsc_signature));
        let _ = writeln!(out, "exponent = {}", self.exponent);
        if let Some(salt_len) = self.pss_salt_len {
            let _ = writeln!(out, "pss_salt_len = {}", salt_len);
        }
        out
    }
}

impl SaveToml for IdDataSigCheckInputs {
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
        let _ = writeln!(out, "exponent = {}", self.exponent);
        let _ = writeln!(out, "e_content = {}", fmt_array(&self.e_content));
        if let Some(salt_len) = self.pss_salt_len {
            let _ = writeln!(out, "pss_salt_len = {}", salt_len);
        }
        out
    }
}

impl SaveToml for IntegrityInputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        // All top-level keys must precede [table] headers in TOML,
        // otherwise they get absorbed into the preceding table.
        let _ = writeln!(out, "comm_in = \"{}\"", self.comm_in);
        let _ = writeln!(out, "salt_in = \"{}\"", self.salt_in);
        let _ = writeln!(out, "r_dg1 = \"{}\"", self.r_dg1);
        let _ = writeln!(
            out,
            "signed_attributes = {}",
            fmt_array(&self.signed_attributes)
        );
        let _ = writeln!(out, "e_content = {}", fmt_array(&self.e_content));
        let _ = writeln!(out);
        let _ = writeln!(out, "[salted_dg1]");
        let _ = writeln!(out, "salt = \"{}\"", self.salted_dg1.salt);
        let _ = writeln!(out, "value = {}", fmt_array(&self.salted_dg1.value));
        let _ = writeln!(out, "hash = \"{}\"", self.salted_dg1.hash);
        let _ = writeln!(out);
        let _ = writeln!(out, "[salted_private_nullifier]");
        let _ = writeln!(out, "salt = \"{}\"", self.salted_private_nullifier.salt);
        let _ = writeln!(out, "value = \"{}\"", self.salted_private_nullifier.value);
        let _ = writeln!(out, "hash = \"{}\"", self.salted_private_nullifier.hash);
        out
    }
}

impl SaveToml for AttestInputs {
    fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "root = \"{}\"", self.root);
        let _ = writeln!(out, "current_date = {}", self.current_date);
        let _ = writeln!(out, "min_age_required = {}", self.min_age_required);
        let _ = writeln!(out, "max_age_required = {}", self.max_age_required);
        let _ = writeln!(out, "service_scope = \"{}\"", self.service_scope);
        let _ = writeln!(out, "service_subscope = \"{}\"", self.service_subscope);
        let _ = writeln!(out, "dg1 = {}", fmt_array(&self.dg1));
        let _ = writeln!(out, "e_content = {}", fmt_array(&self.e_content));
        let _ = writeln!(out, "r_dg1 = \"{}\"", self.r_dg1);
        let _ = writeln!(out, "private_nullifier = \"{}\"", self.private_nullifier);
        let _ = writeln!(out, "nullifier_secret = \"{}\"", self.nullifier_secret);
        let _ = writeln!(out, "leaf_index = \"{}\"", self.leaf_index);
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
        out
    }
}

impl CircuitInputSet for PassportCircuitInputs {
    fn circuit_names(&self) -> Vec<String> {
        self.variant.circuit_names().to_vec()
    }

    fn save_all(&self, base_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(base_dir)?;
        let names = self.variant.circuit_names();
        self.dsc_sig_check
            .save_to_toml_file(base_dir.join(format!("{}.toml", names[0])))?;
        self.id_data_sig_check
            .save_to_toml_file(base_dir.join(format!("{}.toml", names[1])))?;
        self.integrity
            .save_to_toml_file(base_dir.join(format!("{}.toml", names[2])))?;
        self.attest
            .save_to_toml_file(base_dir.join(format!("{}.toml", names[3])))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            mock_generator::{dg1_bytes_with_birthdate_expiry_date, generate_sod},
            mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64},
        },
        rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey},
    };

    /// End-to-end test: generate mock passport data and verify the commitment
    /// chain is self-consistent across all 4 circuit stages.
    #[test]
    fn test_commitment_chain_self_consistent() {
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

        let variant = CircuitVariant::default();
        let config = AttestConfig {
            current_date: 1735689600,
            min_age_required: 18,
            max_age_required: 0,
            ..Default::default()
        };

        let inputs = reader
            .to_passport_inputs(csca_idx, &variant, config)
            .expect("generate inputs");

        // === Verify commitment chain self-consistency ===

        // Stage 1 output: hash(salt_1, country, tbs_cert) → Stage 2 comm_in
        let country_bytes = inputs.dsc_sig_check.country.as_bytes();
        let comm_out_1 = commitment::hash_salt_country_tbs(
            &inputs.dsc_sig_check.salt,
            country_bytes,
            &inputs.id_data_sig_check.tbs_certificate,
        )
        .unwrap();
        assert_eq!(
            commitment::field_to_hex_string(&comm_out_1),
            inputs.id_data_sig_check.comm_in,
            "comm_out_1 mismatch: hash_salt_country_tbs"
        );

        // Private nullifier: hash(dg1, e_content, sod_signature)
        let private_nullifier = commitment::calculate_private_nullifier(
            &inputs.id_data_sig_check.dg1,
            &inputs.id_data_sig_check.e_content,
            &inputs.id_data_sig_check.sod_signature,
        );
        assert_eq!(
            commitment::field_to_hex_string(&private_nullifier),
            inputs.integrity.salted_private_nullifier.value,
            "private_nullifier mismatch"
        );

        // Stage 2 output: hash(salt_2, country, signed_attrs, sa_size, dg1, econtent,
        // nullifier) → Stage 3 comm_in
        let comm_out_2 = commitment::hash_salt_country_sa_dg1_econtent_nullifier(
            &inputs.id_data_sig_check.salt_out,
            country_bytes,
            &inputs.id_data_sig_check.signed_attributes,
            inputs
                .id_data_sig_check
                .signed_attributes
                .iter()
                .position(|&b| {
                    // Find the end of the DER-encoded data by parsing ASN.1 header
                    false
                })
                .unwrap_or(0) as u64,
            &inputs.id_data_sig_check.dg1,
            &inputs.id_data_sig_check.e_content,
            private_nullifier,
        );
        // Note: We need the actual signed_attributes_size for this commitment.
        // Recompute using the extract method's stored value.
        // Since we can't easily get signed_attributes_size from inputs alone,
        // let's verify via round-trip: extract → compute → compare
        let (_, sa_size) = reader.extract_signed_attrs().unwrap();
        let comm_out_2 = commitment::hash_salt_country_sa_dg1_econtent_nullifier(
            &inputs.id_data_sig_check.salt_out,
            country_bytes,
            &inputs.id_data_sig_check.signed_attributes,
            sa_size as u64,
            &inputs.id_data_sig_check.dg1,
            &inputs.id_data_sig_check.e_content,
            private_nullifier,
        )
        .unwrap();
        assert_eq!(
            commitment::field_to_hex_string(&comm_out_2),
            inputs.integrity.comm_in,
            "comm_out_2 mismatch: hash_salt_country_sa_dg1_econtent_nullifier"
        );

        // sod_hash consistent
        let sod_hash = commitment::calculate_sod_hash(&inputs.id_data_sig_check.e_content);
        assert_ne!(
            commitment::field_to_hex_string(&sod_hash),
            ZERO_FIELD,
            "sod_hash should be non-trivial"
        );

        // Verify shared fields between circuits are consistent
        assert_eq!(
            inputs.integrity.salted_dg1.value, inputs.id_data_sig_check.dg1,
            "dg1 should be the same in id_data and integrity"
        );
        assert_eq!(
            inputs.attest.dg1, inputs.integrity.salted_dg1.value,
            "dg1 should be the same in integrity and attest"
        );
        assert_eq!(
            inputs.attest.e_content, inputs.id_data_sig_check.e_content,
            "e_content should be the same in id_data and attest"
        );

        // Verify nullifier is non-trivial
        assert_ne!(
            inputs.integrity.salted_private_nullifier.value, ZERO_FIELD,
            "nullifier should be non-trivial"
        );
    }
}
