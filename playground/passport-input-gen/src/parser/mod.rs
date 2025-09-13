use {
    crate::parser::{
        binary::Binary,
        sod::SOD,
        types::{
            PassportError, MAX_DG1_SIZE, MAX_ECONTENT_SIZE, MAX_SIGNED_ATTRIBUTES_SIZE,
            MAX_TBS_SIZE, SIG_BYTES,
        },
        utils::{find_offset, fit, load_csca_public_keys, to_fixed_array, to_u32},
    },
    base64::{engine::general_purpose::STANDARD, Engine as _},
    noir_bignum_paramgen::compute_barrett_reduction_parameter,
    rsa::{
        pkcs1::DecodeRsaPublicKey, pkcs1v15::Pkcs1v15Sign, pkcs8::DecodePublicKey,
        traits::PublicKeyParts, BigUint, RsaPublicKey,
    },
    sha2::{Digest, Sha256},
    std::{fmt::Write as _, path::Path},
};

mod binary;
mod dsc;
mod oid_registry;
mod sod;
mod types;
mod utils;

/// Parsed passport data
pub struct PassportReader {
    pub dg1: Binary,
    pub sod: SOD,
}

/// Circuit inputs for Noir
pub struct CircuitInputs {
    pub dg1: [u8; MAX_DG1_SIZE],
    pub dg1_padded_length: usize,
    pub current_date: u64,
    pub min_age_required: u8,
    pub max_age_required: u8,
    pub passport_validity_contents: PassportValidityContent,
}

/// Extracted validity contents from SOD
pub struct PassportValidityContent {
    pub signed_attributes: [u8; MAX_SIGNED_ATTRIBUTES_SIZE],
    pub signed_attributes_size: usize,
    pub econtent: [u8; MAX_ECONTENT_SIZE],
    pub econtent_len: usize,
    pub dsc_pubkey: [u8; SIG_BYTES],
    pub dsc_barrett_mu: [u8; SIG_BYTES + 1],
    pub dsc_signature: [u8; SIG_BYTES],
    pub dsc_rsa_exponent: u32,
    pub csc_pubkey: [u8; SIG_BYTES * 2],
    pub csc_barrett_mu: [u8; (SIG_BYTES * 2) + 1],
    pub dsc_cert_signature: [u8; SIG_BYTES * 2],
    pub csc_rsa_exponent: u32,
    pub dg1_hash_offset: usize,
    pub econtent_hash_offset: usize,
    pub dsc_pubkey_offset_in_dsc_cert: usize,
    pub dsc_cert: [u8; MAX_TBS_SIZE],
    pub dsc_cert_len: usize,
}

impl PassportReader {
    /// Extract SignedAttributes (padded + size)
    fn extract_signed_attrs(&self) -> ([u8; MAX_SIGNED_ATTRIBUTES_SIZE], usize) {
        let signed_attrs = self.sod.signer_info.signed_attrs.bytes.to_number_array();
        let size = signed_attrs.len();
        let padded = fit::<MAX_SIGNED_ATTRIBUTES_SIZE>(&signed_attrs);
        (padded, size)
    }

    /// Extract eContent (padded + size + raw bytes)
    fn extract_econtent(&self) -> ([u8; MAX_ECONTENT_SIZE], usize, Vec<u8>) {
        let econtent_bytes = self
            .sod
            .encap_content_info
            .e_content
            .bytes
            .to_number_array();
        let len = econtent_bytes.len();
        let padded = fit::<MAX_ECONTENT_SIZE>(&econtent_bytes);
        (padded, len, econtent_bytes)
    }

    /// Extract DSC public key, exponent, Barrett mu, and signature
    fn extract_dsc(&self) -> ([u8; SIG_BYTES], u32, [u8; SIG_BYTES + 1], [u8; SIG_BYTES]) {
        let der = self
            .sod
            .certificate
            .tbs
            .subject_public_key_info
            .subject_public_key
            .to_number_array();
        let pubkey = RsaPublicKey::from_pkcs1_der(&der).unwrap();

        let modulus = to_fixed_array::<SIG_BYTES>(pubkey.n().to_bytes_be(), "DSC modulus");
        let exponent = to_u32(pubkey.e().to_bytes_be());
        let barrett = to_fixed_array::<{ SIG_BYTES + 1 }>(
            compute_barrett_reduction_parameter(&BigUint::from_bytes_be(&modulus)).to_bytes_be(),
            "DSC Barrett",
        );
        let signature = to_fixed_array::<SIG_BYTES>(
            self.sod.signer_info.signature.to_number_array(),
            "DSC signature",
        );

        (modulus, exponent, barrett, signature)
    }

    /// Extract CSCA public key, exponent, Barrett mu, and signature
    fn extract_csca(
        &self,
        idx: usize,
    ) -> (
        [u8; SIG_BYTES * 2],
        u32,
        [u8; SIG_BYTES * 2 + 1],
        [u8; SIG_BYTES * 2],
    ) {
        let csca_keys = load_csca_public_keys().unwrap();
        let usa_csca = csca_keys.get("USA").unwrap();
        let der = STANDARD
            .decode(usa_csca[idx].public_key.as_bytes())
            .unwrap();
        let pubkey = RsaPublicKey::from_public_key_der(&der).unwrap();

        let modulus = to_fixed_array::<{ SIG_BYTES * 2 }>(pubkey.n().to_bytes_be(), "CSCA modulus");
        let exponent = to_u32(pubkey.e().to_bytes_be());
        let barrett = to_fixed_array::<{ SIG_BYTES * 2 + 1 }>(
            compute_barrett_reduction_parameter(&BigUint::from_bytes_be(&modulus)).to_bytes_be(),
            "CSCA Barrett",
        );
        let signature = to_fixed_array::<{ SIG_BYTES * 2 }>(
            self.sod.certificate.signature.to_number_array(),
            "CSCA signature",
        );

        (modulus, exponent, barrett, signature)
    }

    /// Extract DSC certificate (padded + len + offset of modulus inside cert)
    fn extract_dsc_cert(
        &self,
        dsc_modulus: &[u8; SIG_BYTES],
    ) -> ([u8; MAX_TBS_SIZE], usize, usize) {
        let tbs_bytes = self.sod.certificate.tbs.bytes.to_number_array();
        let cert_len = tbs_bytes.len();
        let padded = fit::<MAX_TBS_SIZE>(&tbs_bytes);
        let pubkey_offset = find_offset(&tbs_bytes, dsc_modulus, "DSC modulus in cert");
        (padded, cert_len, pubkey_offset)
    }
    /// Validate DG1, eContent, and signatures against DSC + CSCA
    pub fn validate(&self) -> Result<usize, PassportError> {
        // 1. Check DG1 hash inside eContent
        let dg1_hash = Sha256::digest(&self.dg1.to_number_array());
        let dg1_from_econtent = self
            .sod
            .encap_content_info
            .e_content
            .data_group_hash_values
            .values
            .get(&1)
            .expect("DG1 hash missing")
            .to_number_array();

        if dg1_from_econtent != dg1_hash.to_vec() {
            return Err(PassportError::Dg1HashMismatch);
        }

        // 2. Check hash(eContent) inside SignedAttributes
        let econtent_hash = Sha256::digest(
            &self
                .sod
                .encap_content_info
                .e_content
                .bytes
                .to_number_array(),
        );
        let mut msg_digest = self
            .sod
            .signer_info
            .signed_attrs
            .message_digest
            .to_number_array();
        if msg_digest.len() > 2 && msg_digest[0] == 0x04 {
            msg_digest = msg_digest[2..].to_vec();
        }

        if econtent_hash.as_slice() != msg_digest {
            return Err(PassportError::EcontentHashMismatch);
        }

        // 3. Verify SignedAttributes signature with DSC
        let signed_attr_hash =
            Sha256::digest(&self.sod.signer_info.signed_attrs.bytes.to_number_array());
        let dsc_pubkey_bytes = self
            .sod
            .certificate
            .tbs
            .subject_public_key_info
            .subject_public_key
            .to_number_array();
        let dsc_pubkey = RsaPublicKey::from_pkcs1_der(&dsc_pubkey_bytes).expect("Invalid DSC key");

        let dsc_signature = self.sod.signer_info.signature.to_number_array();
        dsc_pubkey
            .verify(
                Pkcs1v15Sign::new::<Sha256>(),
                &signed_attr_hash,
                &dsc_signature,
            )
            .map_err(|_| PassportError::DscSignatureInvalid)?;

        let all_csca = load_csca_public_keys().map_err(|_| PassportError::CscaKeysMissing)?;
        let usa_csca = all_csca.get("USA").ok_or(PassportError::NoUsaCsca)?;
        let tbs_bytes = &self.sod.certificate.tbs.bytes.to_number_array();
        let tbs_digest = Sha256::digest(tbs_bytes);
        let csca_signature = &self.sod.certificate.signature.to_number_array();

        for (i, csca) in usa_csca.iter().enumerate() {
            let der = STANDARD.decode(csca.public_key.as_bytes()).unwrap();
            let csca_pubkey = RsaPublicKey::from_public_key_der(&der).unwrap();
            if csca_pubkey
                .verify(Pkcs1v15Sign::new::<Sha256>(), &tbs_digest, csca_signature)
                .is_ok()
            {
                return Ok(i); // Success, return CSCA index
            }
        }

        Err(PassportError::CscaSignatureInvalid)
    }

    /// Convert to circuit inputs for Noir Circuits
    pub fn to_circuit_inputs(
        &self,
        current_date: u64,
        min_age_required: u8,
        max_age_required: u8,
        csca_key_index: usize,
    ) -> CircuitInputs {
        // === Step 1. DG1 ===
        let dg1_padded = fit::<MAX_DG1_SIZE>(&self.dg1.to_number_array());
        let dg1_len = self.dg1.len();

        // === Step 2. SignedAttributes ===
        let (signed_attrs, signed_attributes_size) = self.extract_signed_attrs();

        // === Step 3. eContent ===
        let (econtent, econtent_len, econtent_bytes) = self.extract_econtent();

        // === Step 4. DSC ===
        let (dsc_modulus, dsc_exponent, dsc_barrett, dsc_signature) = self.extract_dsc();

        // === Step 5. CSCA ===
        let (csca_modulus, csca_exponent, csca_barrett, csca_signature) =
            self.extract_csca(csca_key_index);

        // === Step 6. Offsets ===
        let dg1_hash = Sha256::digest(&self.dg1.to_number_array());
        let dg1_hash_offset = find_offset(&econtent_bytes, dg1_hash.as_slice(), "DG1 hash");

        let econtent_hash = Sha256::digest(&econtent_bytes);
        let econtent_hash_offset =
            find_offset(&signed_attrs, econtent_hash.as_slice(), "eContent hash");

        // === Step 7. DSC Certificate ===
        let (dsc_cert, dsc_cert_len, dsc_pubkey_offset) = self.extract_dsc_cert(&dsc_modulus);

        // === Step 8. Build CircuitInputs ===
        CircuitInputs {
            dg1: dg1_padded,
            dg1_padded_length: dg1_len,
            current_date,
            min_age_required,
            max_age_required,
            passport_validity_contents: PassportValidityContent {
                signed_attributes: signed_attrs,
                signed_attributes_size,
                econtent,
                econtent_len,
                dsc_pubkey: dsc_modulus,
                dsc_barrett_mu: dsc_barrett,
                dsc_signature,
                dsc_rsa_exponent: dsc_exponent,
                csc_pubkey: csca_modulus,
                csc_barrett_mu: csca_barrett,
                dsc_cert_signature: csca_signature,
                csc_rsa_exponent: csca_exponent,
                dg1_hash_offset,
                econtent_hash_offset,
                dsc_pubkey_offset_in_dsc_cert: dsc_pubkey_offset,
                dsc_cert,
                dsc_cert_len,
            },
        }
    }
}

impl CircuitInputs {
    pub fn to_toml_string(&self) -> String {
        let mut out = String::new();
        writeln!(out, "dg1 = {:?}", self.dg1).unwrap();
        writeln!(out, "dg1_padded_length = {}", self.dg1_padded_length).unwrap();
        writeln!(out, "current_date = {}", self.current_date).unwrap();
        writeln!(out, "min_age_required = {}", self.min_age_required).unwrap();
        writeln!(out, "max_age_required = {}", self.max_age_required).unwrap();
        writeln!(out, "\n[passport_validity_contents]").unwrap();

        let pvc = &self.passport_validity_contents;
        writeln!(out, "signed_attributes = {:?}", pvc.signed_attributes).unwrap();
        writeln!(
            out,
            "signed_attributes_size = {}",
            pvc.signed_attributes_size
        )
        .unwrap();
        writeln!(out, "econtent = {:?}", pvc.econtent).unwrap();
        writeln!(out, "econtent_len = {}", pvc.econtent_len).unwrap();
        writeln!(out, "dsc_signature = {:?}", pvc.dsc_signature).unwrap();
        writeln!(out, "dsc_rsa_exponent = {}", pvc.dsc_rsa_exponent).unwrap();
        writeln!(out, "dsc_pubkey = {:?}", pvc.dsc_pubkey).unwrap();
        writeln!(out, "dsc_barrett_mu = {:?}", pvc.dsc_barrett_mu).unwrap();
        writeln!(out, "csc_pubkey = {:?}", pvc.csc_pubkey).unwrap();
        writeln!(out, "csc_barrett_mu = {:?}", pvc.csc_barrett_mu).unwrap();
        writeln!(out, "dsc_cert_signature = {:?}", pvc.dsc_cert_signature).unwrap();
        writeln!(out, "csc_rsa_exponent = {}", pvc.csc_rsa_exponent).unwrap();
        writeln!(out, "dg1_hash_offset = {}", pvc.dg1_hash_offset).unwrap();
        writeln!(out, "econtent_hash_offset = {}", pvc.econtent_hash_offset).unwrap();
        writeln!(
            out,
            "dsc_pubkey_offset_in_dsc_cert = {}",
            pvc.dsc_pubkey_offset_in_dsc_cert
        )
        .unwrap();
        writeln!(out, "dsc_cert = {:?}", pvc.dsc_cert).unwrap();
        writeln!(out, "dsc_cert_len = {}", pvc.dsc_cert_len).unwrap();
        out
    }

    pub fn save_to_toml_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        std::fs::write(path, self.to_toml_string())
    }
}
