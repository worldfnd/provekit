use {
    crate::parser::{
        binary::Binary,
        dsc::{SubjectPublicKeyInfo, TbsCertificate, DSC},
        sod::SOD,
        types::{
            DataGroupHashValues, DigestAlgorithm, EContent, EncapContentInfo, SignatureAlgorithm,
            SignatureAlgorithmName, SignedAttrs, SignerIdentifier, SignerInfo, MAX_DG1_SIZE,
        },
    },
    rsa::{
        pkcs1::EncodeRsaPublicKey,
        pkcs1v15::SigningKey,
        signature::{SignatureEncoding, Signer},
        RsaPrivateKey, RsaPublicKey,
    },
    sha2::{Digest, Sha256},
    std::collections::HashMap,
};

/// Build a fake DG1 (MRZ) with given birthdate and expiry dates.
/// Birthdate and expiry are encoded as YYMMDD and inserted into the MRZ
/// positions. The rest of the bytes are filled with `<` characters and the
/// final two bytes are zeroed.
pub fn dg1_bytes_with_birthdate_expiry_date(birthdate: &[u8; 6], expiry: &[u8; 6]) -> Vec<u8> {
    let mut dg1 = vec![b'<'; MAX_DG1_SIZE];
    let mrz_offset = 5;
    dg1[mrz_offset + 57..mrz_offset + 57 + 6].copy_from_slice(birthdate);
    dg1[mrz_offset + 65..mrz_offset + 65 + 6].copy_from_slice(expiry);
    dg1[93] = 0;
    dg1[94] = 0;
    dg1
}

/// Generate a synthetic SOD structure for the given DG1 and key pairs.
pub fn generate_fake_sod(
    dg1: &[u8],
    dsc_priv: &RsaPrivateKey,
    dsc_pub: &RsaPublicKey,
    csca_priv: &RsaPrivateKey,
    _csca_pub: &RsaPublicKey,
) -> SOD {
    // Hash DG1 and build eContent
    let dg1_hash = Sha256::digest(dg1);
    let econtent_bytes = dg1_hash.to_vec();
    let mut dg_map = HashMap::new();
    dg_map.insert(1u32, Binary::from_slice(&dg1_hash));
    let data_group_hashes = DataGroupHashValues { values: dg_map };
    let econtent = EContent {
        version:                0,
        hash_algorithm:         DigestAlgorithm::SHA256,
        data_group_hash_values: data_group_hashes,
        bytes:                  Binary::from_slice(&econtent_bytes),
    };
    let encap_content_info = EncapContentInfo {
        e_content_type: "mRTDSignatureData".to_string(),
        e_content:      econtent,
    };

    // Hash eContent and build SignedAttributes
    let econtent_hash = Sha256::digest(&econtent_bytes);
    let signed_attr_bytes = econtent_hash.to_vec();
    let signed_attrs = SignedAttrs {
        content_type:   "data".to_string(),
        message_digest: Binary::from_slice(&econtent_hash),
        signing_time:   None,
        bytes:          Binary::from_slice(&signed_attr_bytes),
    };

    // Sign SignedAttributes with DSC private key
    let dsc_signer = SigningKey::<Sha256>::new(dsc_priv.clone());
    let dsc_signature = dsc_signer.sign(&signed_attr_bytes).to_bytes();
    let signer_info = SignerInfo {
        version: 1,
        signed_attrs,
        digest_algorithm: DigestAlgorithm::SHA256,
        signature_algorithm: SignatureAlgorithm {
            name:       SignatureAlgorithmName::Sha256WithRsaEncryption,
            parameters: None,
        },
        signature: Binary::from_slice(&dsc_signature),
        sid: SignerIdentifier {
            issuer_and_serial_number: None,
            subject_key_identifier:   None,
        },
    };

    // Build fake DSC certificate (TBS = DER of DSC public key)
    let dsc_pub_der = dsc_pub.to_pkcs1_der().expect("pkcs1 der").to_vec();
    let tbs_bytes = dsc_pub_der.clone();

    let csca_signer = SigningKey::<Sha256>::new(csca_priv.clone());
    let csca_signature = csca_signer.sign(&tbs_bytes).to_bytes();

    let dsc_cert = DSC {
        tbs:                 TbsCertificate {
            version:                 1,
            serial_number:           Binary::from_slice(&[1]),
            signature_algorithm:     SignatureAlgorithm {
                name:       SignatureAlgorithmName::Sha256WithRsaEncryption,
                parameters: None,
            },
            issuer:                  "CSCA".to_string(),
            validity_not_before:     chrono::Utc::now()
                - chrono::Duration::from_std(std::time::Duration::from_secs(
                    5 * 365 * 24 * 60 * 60,
                ))
                .expect("valid duration before 5 years"), // before 5 year date
            validity_not_after:      chrono::Utc::now()
                + chrono::Duration::from_std(std::time::Duration::from_secs(
                    5 * 365 * 24 * 60 * 60,
                ))
                .expect("valid duration after 5 years"), // after 5 years
            subject:                 "DSC".to_string(),
            subject_public_key_info: SubjectPublicKeyInfo {
                signature_algorithm: SignatureAlgorithm {
                    name:       SignatureAlgorithmName::RsaEncryption,
                    parameters: None,
                },
                subject_public_key:  Binary::from_slice(&dsc_pub_der),
            },
            issuer_unique_id:        None,
            subject_unique_id:       None,
            extensions:              HashMap::new(),
            bytes:                   Binary::from_slice(&tbs_bytes),
        },
        signature_algorithm: SignatureAlgorithm {
            name:       SignatureAlgorithmName::Sha256WithRsaEncryption,
            parameters: None,
        },
        signature:           Binary::from_slice(&csca_signature),
    };

    SOD {
        version: 1,
        digest_algorithms: vec![DigestAlgorithm::SHA256],
        encap_content_info,
        signer_info,
        certificate: dsc_cert,
        bytes: Binary::new(vec![]),
    }
}

/// Generate a synthetic SOD with a TBS certificate padded to `tbs_actual_len` bytes.
///
/// The TBS bytes consist of:
///   1. DSC public key in PKCS#1 DER format (~270 bytes)
///   2. Non-zero incrementing byte pattern filling up to `tbs_actual_len`
///
/// This produces a TBS > 720 bytes, suitable for testing the 1300-byte path.
/// The CSCA signs this padded TBS just like `generate_fake_sod` does.
pub fn generate_fake_sod_with_padded_tbs(
    dg1: &[u8],
    dsc_priv: &RsaPrivateKey,
    dsc_pub: &RsaPublicKey,
    csca_priv: &RsaPrivateKey,
    _csca_pub: &RsaPublicKey,
    tbs_actual_len: usize,
) -> SOD {
    // Hash DG1 and build eContent (same as generate_fake_sod)
    let dg1_hash = Sha256::digest(dg1);
    let econtent_bytes = dg1_hash.to_vec();
    let mut dg_map = HashMap::new();
    dg_map.insert(1u32, Binary::from_slice(&dg1_hash));
    let data_group_hashes = DataGroupHashValues { values: dg_map };
    let econtent = EContent {
        version:                0,
        hash_algorithm:         DigestAlgorithm::SHA256,
        data_group_hash_values: data_group_hashes,
        bytes:                  Binary::from_slice(&econtent_bytes),
    };
    let encap_content_info = EncapContentInfo {
        e_content_type: "mRTDSignatureData".to_string(),
        e_content:      econtent,
    };

    // Hash eContent and build SignedAttributes
    let econtent_hash = Sha256::digest(&econtent_bytes);
    let signed_attr_bytes = econtent_hash.to_vec();
    let signed_attrs = SignedAttrs {
        content_type:   "data".to_string(),
        message_digest: Binary::from_slice(&econtent_hash),
        signing_time:   None,
        bytes:          Binary::from_slice(&signed_attr_bytes),
    };

    // Sign SignedAttributes with DSC private key
    let dsc_signer = SigningKey::<Sha256>::new(dsc_priv.clone());
    let dsc_signature = dsc_signer.sign(&signed_attr_bytes).to_bytes();
    let signer_info = SignerInfo {
        version: 1,
        signed_attrs,
        digest_algorithm: DigestAlgorithm::SHA256,
        signature_algorithm: SignatureAlgorithm {
            name:       SignatureAlgorithmName::Sha256WithRsaEncryption,
            parameters: None,
        },
        signature: Binary::from_slice(&dsc_signature),
        sid: SignerIdentifier {
            issuer_and_serial_number: None,
            subject_key_identifier:   None,
        },
    };

    // Build padded TBS: DSC pubkey DER + incrementing non-zero pattern
    let dsc_pub_der = dsc_pub.to_pkcs1_der().expect("pkcs1 der").to_vec();
    let mut tbs_bytes = dsc_pub_der.clone();

    // Fill remaining bytes up to tbs_actual_len with non-zero pattern
    let mut next_byte = (tbs_bytes.len() as u8).wrapping_add(1);
    while tbs_bytes.len() < tbs_actual_len {
        tbs_bytes.push(next_byte);
        next_byte = if next_byte == 253 { 1 } else { next_byte + 1 };
    }

    // CSCA signs the padded TBS
    let csca_signer = SigningKey::<Sha256>::new(csca_priv.clone());
    let csca_signature = csca_signer.sign(&tbs_bytes).to_bytes();

    let dsc_cert = DSC {
        tbs:                 TbsCertificate {
            version:                 1,
            serial_number:           Binary::from_slice(&[1]),
            signature_algorithm:     SignatureAlgorithm {
                name:       SignatureAlgorithmName::Sha256WithRsaEncryption,
                parameters: None,
            },
            issuer:                  "CSCA".to_string(),
            validity_not_before:     chrono::Utc::now()
                - chrono::Duration::from_std(std::time::Duration::from_secs(
                    5 * 365 * 24 * 60 * 60,
                ))
                .expect("valid duration before 5 years"),
            validity_not_after:      chrono::Utc::now()
                + chrono::Duration::from_std(std::time::Duration::from_secs(
                    5 * 365 * 24 * 60 * 60,
                ))
                .expect("valid duration after 5 years"),
            subject:                 "DSC".to_string(),
            subject_public_key_info: SubjectPublicKeyInfo {
                signature_algorithm: SignatureAlgorithm {
                    name:       SignatureAlgorithmName::RsaEncryption,
                    parameters: None,
                },
                subject_public_key:  Binary::from_slice(&dsc_pub_der),
            },
            issuer_unique_id:        None,
            subject_unique_id:       None,
            extensions:              HashMap::new(),
            bytes:                   Binary::from_slice(&tbs_bytes),
        },
        signature_algorithm: SignatureAlgorithm {
            name:       SignatureAlgorithmName::Sha256WithRsaEncryption,
            parameters: None,
        },
        signature:           Binary::from_slice(&csca_signature),
    };

    SOD {
        version: 1,
        digest_algorithms: vec![DigestAlgorithm::SHA256],
        encap_content_info,
        signer_info,
        certificate: dsc_cert,
        bytes: Binary::new(vec![]),
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64},
            PassportReader,
        },
        base64::{engine::general_purpose::STANDARD, Engine as _},
        chrono::Utc,
        rsa::pkcs8::DecodePrivateKey,
    };

    fn load_csca_mock_private_key() -> RsaPrivateKey {
        let der = STANDARD
            .decode(MOCK_CSCA_PRIV_KEY_B64)
            .expect("decode CSCA private key");
        RsaPrivateKey::from_pkcs8_der(&der).expect("CSCA key")
    }

    fn load_dsc_mock_private_key() -> RsaPrivateKey {
        let der = STANDARD
            .decode(MOCK_DSC_PRIV_KEY_B64)
            .expect("decode DSC private key");
        RsaPrivateKey::from_pkcs8_der(&der).expect("DSC key")
    }

    #[test]
    fn test_generate_and_validate_sod() {
        use crate::MerkleAge720Config;

        let csca_priv = load_csca_mock_private_key();
        let csca_pub = csca_priv.to_public_key();
        let dsc_priv = load_dsc_mock_private_key();
        let dsc_pub = dsc_priv.to_public_key();

        let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
        let sod = generate_fake_sod(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub);
        let reader = PassportReader::new(
            Binary::from_slice(&dg1),
            sod,
            true,
            Some(csca_pub),
        );
        assert!(reader.validate().is_ok());

        let config = MerkleAge720Config {
            current_date: Utc::now().timestamp() as u64,
            min_age_required: 18,
            max_age_required: 70,
            ..Default::default()
        };

        let inputs = reader
            .to_merkle_age_720_inputs(0, config)
            .expect("to merkle age 720 inputs");

        // Verify each circuit's TOML can be generated
        let dsc_toml = inputs.add_dsc.to_toml_string();
        let id_data_toml = inputs.add_id_data.to_toml_string();
        let integrity_toml = inputs.add_integrity.to_toml_string();
        let attest_toml = inputs.attest.to_toml_string();

        assert!(!dsc_toml.is_empty());
        assert!(!id_data_toml.is_empty());
        assert!(!integrity_toml.is_empty());
        assert!(!attest_toml.is_empty());

        println!("=== t_add_dsc_720 ===\n{}", dsc_toml);
        println!("=== t_add_id_data_720 ===\n{}", id_data_toml);
        println!("=== t_add_integrity_commit ===\n{}", integrity_toml);
        println!("=== t_attest ===\n{}", attest_toml);
    }
}
