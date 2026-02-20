use {
    crate::parser::{
        binary::Binary,
        dsc::{SubjectPublicKeyInfo, TbsCertificate, DSC},
        sod::SOD,
        types::{
            DataGroupHash, DataGroupHashValues, DigestAlgorithm, EContent, EncapContentInfo,
            LDSSecurityObject, SignatureAlgorithm, SignatureAlgorithmName, SignedAttrs,
            SignerIdentifier, SignerInfo, MAX_DG1_SIZE, MAX_ECONTENT_SIZE,
            MAX_SIGNED_ATTRIBUTES_SIZE,
        },
    },
    rasn::{
        der,
        types::{Any, BitString, Integer, ObjectIdentifier, OctetString},
    },
    rasn_cms::Attribute,
    rasn_pkix::AlgorithmIdentifier,
    rsa::{
        pkcs1::EncodeRsaPublicKey,
        pkcs1v15::SigningKey,
        signature::{SignatureEncoding, Signer},
        RsaPrivateKey, RsaPublicKey,
    },
    sha2::{Digest, Sha256},
    std::collections::{BTreeSet, HashMap},
};

// ============================================================================
// Well-known OIDs
// ============================================================================

/// SHA-256: 2.16.840.1.101.3.4.2.1
fn oid_sha256() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![2, 16, 840, 1, 101, 3, 4, 2, 1].into())
}

/// sha256WithRSAEncryption: 1.2.840.113549.1.1.11
fn oid_sha256_with_rsa() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![1, 2, 840, 113549, 1, 1, 11].into())
}

/// rsaEncryption: 1.2.840.113549.1.1.1
fn oid_rsa_encryption() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![1, 2, 840, 113549, 1, 1, 1].into())
}

/// mRTDSignatureData (id-ldsSecurityObject): 2.23.136.1.1.1
fn oid_mrtd_signature_data() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![2, 23, 136, 1, 1, 1].into())
}

/// id-contentType: 1.2.840.113549.1.9.3
fn oid_content_type() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![1, 2, 840, 113549, 1, 9, 3].into())
}

/// id-messageDigest: 1.2.840.113549.1.9.4
fn oid_message_digest() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![1, 2, 840, 113549, 1, 9, 4].into())
}

/// id-ce-basicConstraints: 2.5.29.19
fn oid_basic_constraints() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![2, 5, 29, 19].into())
}

/// id-ce-keyUsage: 2.5.29.15
fn oid_key_usage() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![2, 5, 29, 15].into())
}

/// id-ce-subjectKeyIdentifier: 2.5.29.14
fn oid_subject_key_identifier() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![2, 5, 29, 14].into())
}

/// id-at-commonName: 2.5.4.3
fn oid_common_name() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into())
}

/// id-at-countryName: 2.5.4.6
fn oid_country_name() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![2, 5, 4, 6].into())
}

/// id-at-organizationName: 2.5.4.10
fn oid_organization_name() -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(vec![2, 5, 4, 10].into())
}

// ============================================================================
// ICAO check digit computation
// ============================================================================

/// Compute an ICAO 9303 check digit over a byte slice.
/// Characters are mapped to values: 0-9 -> 0-9, A-Z -> 10-35, '<' -> 0.
/// The weighted sum (weights cycling 7, 3, 1) modulo 10 gives the digit.
fn compute_check_digit(data: &[u8]) -> u8 {
    let weights = [7u32, 3, 1];
    let sum: u32 = data
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let val = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'A'..=b'Z' => (b - b'A' + 10) as u32,
                _ => 0,
            };
            val * weights[i % 3]
        })
        .sum();
    b'0' + (sum % 10) as u8
}

// ============================================================================
// DG1 builder
// ============================================================================

/// Build a realistic DG1 (MRZ) with given birthdate and expiry dates.
///
/// The result is a 95-byte structure:
///   - bytes 0..5:   ASN.1 tag prefix (0x61 0x5B 0x5F 0x1F 0x58)
///   - bytes 5..95:  90-byte TD3 (passport) MRZ with realistic fields
///
/// Birthdate and expiry are encoded as YYMMDD (6 ASCII digit bytes).
/// MRZ line 1 (positions 0..44): document type, country, name
/// MRZ line 2 (positions 44..88): doc number, nationality, DOB, gender, expiry,
/// optional The final two bytes (positions 88,89) are the composite check digit
/// and a filler.
pub fn dg1_bytes_with_birthdate_expiry_date(birthdate: &[u8; 6], expiry: &[u8; 6]) -> Vec<u8> {
    // check valid yymmdd format
    debug_assert!(birthdate.iter().all(|b| b.is_ascii_digit()));

    // ASN.1 tag prefix for DG1: Tag 0x61, Length 0x5B, then 0x5F 0x1F 0x58
    let header: [u8; 5] = [0x61, 0x5b, 0x5f, 0x1f, 0x58];

    let mut mrz = [b'<'; 90];

    // --- MRZ Line 1 (44 chars) ---
    // Document type
    mrz[0] = b'P';
    mrz[1] = b'<';
    // Issuing country (Utopia – ICAO test code)
    mrz[2..5].copy_from_slice(b"UTO");
    // Name: DOE<<JOHN<MOCK (pad rest with '<')
    let name = b"DOE<<JOHN<MOCK";
    mrz[5..5 + name.len()].copy_from_slice(name);
    // Remaining positions 5+14..44 are already '<'

    // --- MRZ Line 2 (44 chars, at mrz[44..88]) ---
    // Document number (9 chars)
    let doc_number = b"L898902C3";
    mrz[44..53].copy_from_slice(doc_number);
    // Check digit for document number
    mrz[53] = compute_check_digit(&mrz[44..53]);
    // Nationality
    mrz[54..57].copy_from_slice(b"UTO");
    // Date of birth (YYMMDD)
    mrz[57..63].copy_from_slice(birthdate);
    // Check digit for date of birth
    mrz[63] = compute_check_digit(birthdate);
    // Gender
    mrz[64] = b'M';
    // Date of expiry (YYMMDD)
    mrz[65..71].copy_from_slice(expiry);
    // Check digit for date of expiry
    mrz[71] = compute_check_digit(expiry);
    // Optional data (mrz[72..86]) stays '<'
    // Check digit for optional data
    mrz[86] = compute_check_digit(&mrz[72..86]);
    // Composite check digit over doc_number+check, DOB+check, expiry+check,
    // optional+check
    let composite_data: Vec<u8> = [
        &mrz[44..54], // doc number + check
        &mrz[57..64], // DOB + check
        &mrz[65..72], // expiry + check
        &mrz[72..87], // optional + check
    ]
    .concat();
    mrz[87] = compute_check_digit(&composite_data);
    // Positions 88, 89 are filler (null terminators per convention)
    mrz[88] = 0;
    mrz[89] = 0;

    let mut dg1 = Vec::with_capacity(MAX_DG1_SIZE);
    dg1.extend_from_slice(&header);
    dg1.extend_from_slice(&mrz);
    assert_eq!(dg1.len(), MAX_DG1_SIZE);
    dg1
}

// ============================================================================
// eContent builder (DER-encoded LDSSecurityObject)
// ============================================================================

/// Build a DER-encoded LDSSecurityObject containing the SHA-256 hash of DG1
/// and a dummy DG2 hash, and return both the encoded bytes and the raw DG1
/// hash.
fn build_econtent_bytes(dg1: &[u8]) -> Vec<u8> {
    let dg1_hash = Sha256::digest(dg1);

    let lds_security_object = LDSSecurityObject {
        version:                Integer::from(0),
        hash_algorithm:         AlgorithmIdentifier {
            algorithm:  oid_sha256(),
            parameters: None,
        },
        data_group_hash_values: vec![
            DataGroupHash {
                data_group_number:     Integer::from(1),
                data_group_hash_value: OctetString::from(dg1_hash.to_vec()),
            },
            DataGroupHash {
                data_group_number:     Integer::from(2),
                data_group_hash_value: OctetString::from(vec![0x01u8; 32]),
            },
        ]
        .into(),
        lds_version_info:       None,
    };

    let econtent_bytes =
        der::encode(&lds_security_object).expect("Failed to encode LDSSecurityObject");
    assert!(
        econtent_bytes.len() <= MAX_ECONTENT_SIZE,
        "eContent DER ({} bytes) exceeds MAX_ECONTENT_SIZE ({})",
        econtent_bytes.len(),
        MAX_ECONTENT_SIZE
    );
    econtent_bytes
}

// ============================================================================
// SignedAttributes builder (DER-encoded CMS Attribute SET)
// ============================================================================

/// Build a DER-encoded SET OF Attribute containing contentType and
/// messageDigest, matching the reconstruction logic in
/// `SOD::parse_signed_attrs`.
fn build_signed_attrs_bytes(econtent_bytes: &[u8]) -> Vec<u8> {
    let econtent_hash = Sha256::digest(econtent_bytes);

    // contentType attribute: OID -> mRTDSignatureData
    let content_type_value = der::encode(&oid_mrtd_signature_data()).expect("encode mRTD OID");
    let content_type_attr = Attribute {
        r#type: oid_content_type(),
        values: [Any::new(content_type_value)].into(),
    };

    // messageDigest attribute: OCTET STRING of eContent hash
    let digest_value =
        der::encode(&OctetString::from(econtent_hash.to_vec())).expect("encode digest");
    let message_digest_attr = Attribute {
        r#type: oid_message_digest(),
        values: [Any::new(digest_value)].into(),
    };

    // Encode as SET OF Attribute (BTreeSet ensures DER SET-OF ordering)
    let signed_attrs_set: BTreeSet<Attribute> = [content_type_attr, message_digest_attr]
        .into_iter()
        .collect();

    let signed_attrs_bytes =
        der::encode(&signed_attrs_set).expect("Failed to encode SignedAttributes");
    assert!(
        signed_attrs_bytes.len() <= MAX_SIGNED_ATTRIBUTES_SIZE,
        "SignedAttributes DER ({} bytes) exceeds MAX_SIGNED_ATTRIBUTES_SIZE ({})",
        signed_attrs_bytes.len(),
        MAX_SIGNED_ATTRIBUTES_SIZE
    );
    signed_attrs_bytes
}

// ============================================================================
// TBS Certificate builder (DER-encoded X.509 TBSCertificate)
// ============================================================================

/// Build a Distinguished Name containing CN + C + O attributes.
fn build_dn(cn: &str, country: &str, org: &str) -> rasn_pkix::Name {
    use rasn_pkix::{AttributeTypeAndValue, Name, RdnSequence, RelativeDistinguishedName};

    let cn_attr = AttributeTypeAndValue {
        r#type: oid_common_name(),
        value:  Any::new(
            der::encode(&rasn::types::Utf8String::from(cn.to_string())).expect("encode CN"),
        ),
    };
    let c_attr = AttributeTypeAndValue {
        r#type: oid_country_name(),
        value:  Any::new(
            der::encode(
                &rasn::types::PrintableString::try_from(country.to_string())
                    .expect("valid country"),
            )
            .expect("encode C"),
        ),
    };
    let o_attr = AttributeTypeAndValue {
        r#type: oid_organization_name(),
        value:  Any::new(
            der::encode(&rasn::types::Utf8String::from(org.to_string())).expect("encode O"),
        ),
    };

    // Each attribute in its own RDN (standard multi-RDN approach)
    Name::RdnSequence(RdnSequence::from(vec![
        RelativeDistinguishedName::from(BTreeSet::from([c_attr])),
        RelativeDistinguishedName::from(BTreeSet::from([o_attr])),
        RelativeDistinguishedName::from(BTreeSet::from([cn_attr])),
    ]))
}

/// Build X.509 extensions for a DSC certificate:
///   - basicConstraints (critical, cA=false)
///   - keyUsage (critical, digitalSignature)
///   - subjectKeyIdentifier (non-critical, SHA-256 of public key)
fn build_dsc_extensions(dsc_pub: &RsaPublicKey) -> rasn_pkix::Extensions {
    use rasn_pkix::Extension;

    // basicConstraints: SEQUENCE { BOOLEAN FALSE }
    // DER: 30 03 01 01 00  (SEQUENCE { BOOLEAN false })
    let basic_constraints_value = vec![0x30, 0x03, 0x01, 0x01, 0x00];
    let basic_constraints = Extension {
        extn_id:    oid_basic_constraints(),
        critical:   true,
        extn_value: OctetString::from(basic_constraints_value),
    };

    // keyUsage: BIT STRING with digitalSignature (bit 0)
    // DER: 03 02 07 80  (BIT STRING, 7 unused bits, byte 0x80 = bit 0 set)
    let key_usage_value = vec![0x03, 0x02, 0x07, 0x80];
    let key_usage = Extension {
        extn_id:    oid_key_usage(),
        critical:   true,
        extn_value: OctetString::from(key_usage_value),
    };

    // subjectKeyIdentifier: OCTET STRING wrapping SHA-256 of DER public key
    let pub_der = dsc_pub.to_pkcs1_der().expect("pkcs1 der").to_vec();
    let ski_hash = Sha256::digest(&pub_der);
    // Wrap in OCTET STRING: 04 20 <32 bytes>
    let mut ski_value = vec![0x04, 0x20];
    ski_value.extend_from_slice(&ski_hash);
    let ski = Extension {
        extn_id:    oid_subject_key_identifier(),
        critical:   false,
        extn_value: OctetString::from(ski_value),
    };

    vec![basic_constraints, key_usage, ski].into()
}

/// Build a DER-encoded rasn_pkix::TbsCertificate for a DSC signed by CSCA.
fn build_tbs_certificate_bytes(dsc_pub: &RsaPublicKey) -> Vec<u8> {
    use rasn_pkix::{
        SubjectPublicKeyInfo as RasnSpki, TbsCertificate as RasnTbs, Validity, Version,
    };

    // NULL parameters for RSA algorithms
    let null_params = der::encode(&()).expect("encode NULL");

    let spki = RasnSpki {
        algorithm:          AlgorithmIdentifier {
            algorithm:  oid_rsa_encryption(),
            parameters: Some(Any::new(null_params.clone())),
        },
        subject_public_key: BitString::from_vec(
            dsc_pub.to_pkcs1_der().expect("pkcs1 der").to_vec(),
        ),
    };

    // Validity: from 5 years ago to 5 years from now
    let now = chrono::Utc::now();
    let five_years_secs: i64 = 5 * 365 * 24 * 60 * 60;
    let not_before_ts = now.timestamp() - five_years_secs;
    let not_after_ts = now.timestamp() + five_years_secs;

    let not_before_dt =
        chrono::DateTime::from_timestamp(not_before_ts, 0).expect("valid timestamp");
    let not_after_dt = chrono::DateTime::from_timestamp(not_after_ts, 0).expect("valid timestamp");

    let validity = Validity {
        not_before: rasn_pkix::Time::Utc(not_before_dt),
        not_after:  rasn_pkix::Time::Utc(not_after_dt),
    };

    let tbs = RasnTbs {
        version: Version::V3,
        serial_number: Integer::from(2),
        signature: AlgorithmIdentifier {
            algorithm:  oid_sha256_with_rsa(),
            parameters: Some(Any::new(null_params)),
        },
        issuer: build_dn("Mock CSCA", "UT", "Mock Passport Authority"),
        validity,
        subject: build_dn("Mock DSC", "UT", "Mock Passport Authority"),
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(build_dsc_extensions(dsc_pub)),
    };

    der::encode(&tbs).expect("Failed to encode TbsCertificate")
}

// ============================================================================
// SOD assembly
// ============================================================================

/// Core SOD builder: given DG1 data and a pre-built TBS byte vector, construct
/// the full SOD with all cryptographic signatures and proper DER-encoded
/// internal structures.
fn build_sod_from_tbs(
    dg1: &[u8],
    dsc_priv: &RsaPrivateKey,
    dsc_pub: &RsaPublicKey,
    csca_priv: &RsaPrivateKey,
    tbs_bytes: Vec<u8>,
) -> SOD {
    // --- eContent: DER-encoded LDSSecurityObject ---
    let econtent_bytes = build_econtent_bytes(dg1);

    let dg1_hash = Sha256::digest(dg1);
    let mut dg_map = HashMap::new();
    dg_map.insert(1u32, Binary::from_slice(&dg1_hash));
    dg_map.insert(2u32, Binary::from_slice(&vec![0x01u8; 32]));
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

    // --- SignedAttributes: DER-encoded SET OF Attribute ---
    let signed_attr_bytes = build_signed_attrs_bytes(&econtent_bytes);

    let econtent_hash = Sha256::digest(&econtent_bytes);
    let signed_attrs = SignedAttrs {
        content_type:   "mRTDSignatureData".to_string(),
        message_digest: Binary::from_slice(
            // Store the raw messageDigest value (OCTET STRING DER of the hash)
            &der::encode(&OctetString::from(econtent_hash.to_vec())).expect("encode digest"),
        ),
        signing_time:   None,
        bytes:          Binary::from_slice(&signed_attr_bytes),
    };

    // --- Sign SignedAttributes with DSC private key ---
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

    // --- Build DSC certificate with real TBS ---
    let dsc_pub_der = dsc_pub.to_pkcs1_der().expect("pkcs1 der").to_vec();

    // CSCA signs the DER-encoded TBS bytes
    let csca_signer = SigningKey::<Sha256>::new(csca_priv.clone());
    let csca_signature = csca_signer.sign(&tbs_bytes).to_bytes();

    let dsc_cert = DSC {
        tbs:                 TbsCertificate {
            version:                 2, // v3
            serial_number:           Binary::from_slice(&[2]),
            signature_algorithm:     SignatureAlgorithm {
                name:       SignatureAlgorithmName::Sha256WithRsaEncryption,
                parameters: None,
            },
            issuer:                  "countryName=UT, organizationName=Mock Passport Authority, \
                                      commonName=Mock CSCA"
                .to_string(),
            validity_not_before:     chrono::Utc::now()
                - chrono::Duration::from_std(std::time::Duration::from_secs(
                    5 * 365 * 24 * 60 * 60,
                ))
                .expect("valid duration"),
            validity_not_after:      chrono::Utc::now()
                + chrono::Duration::from_std(std::time::Duration::from_secs(
                    5 * 365 * 24 * 60 * 60,
                ))
                .expect("valid duration"),
            subject:                 "countryName=UT, organizationName=Mock Passport Authority, \
                                      commonName=Mock DSC"
                .to_string(),
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
        version: 3,
        digest_algorithms: vec![DigestAlgorithm::SHA256],
        encap_content_info,
        signer_info,
        certificate: dsc_cert,
        bytes: Binary::new(vec![]),
    }
}

/// Generate a synthetic SOD with proper DER-encoded internal structures.
///
/// The SOD contains:
///   - eContent: DER-encoded LDSSecurityObject with DG1 + DG2 hashes
///   - SignedAttributes: DER-encoded CMS Attribute SET (contentType +
///     messageDigest)
///   - TBS Certificate: DER-encoded X.509 TBSCertificate with extensions
///   - All proper RSA signatures (DSC signs signedAttrs, CSCA signs TBS)
pub fn generate_sod(
    dg1: &[u8],
    dsc_priv: &RsaPrivateKey,
    dsc_pub: &RsaPublicKey,
    csca_priv: &RsaPrivateKey,
    _csca_pub: &RsaPublicKey,
) -> SOD {
    let tbs_bytes = build_tbs_certificate_bytes(dsc_pub);
    build_sod_from_tbs(dg1, dsc_priv, dsc_pub, csca_priv, tbs_bytes)
}

/// Generate a synthetic SOD with a TBS certificate padded to
/// `tbs_actual_len` bytes.
///
/// First builds a realistic DER-encoded TBSCertificate, then extends it
/// with a large opaque X.509 extension to reach the target length.
/// If the base TBS already exceeds `tbs_actual_len`, it is used as-is.
pub fn generate_sod_with_padded_tbs(
    dg1: &[u8],
    dsc_priv: &RsaPrivateKey,
    dsc_pub: &RsaPublicKey,
    csca_priv: &RsaPrivateKey,
    _csca_pub: &RsaPublicKey,
    tbs_actual_len: usize,
) -> SOD {
    let base_tbs = build_tbs_certificate_bytes(dsc_pub);

    let tbs_bytes = if base_tbs.len() >= tbs_actual_len {
        base_tbs
    } else {
        // Rebuild with a padding extension to hit the target length.
        // We compute how many extra bytes we need and add a dummy extension.
        build_padded_tbs_certificate_bytes(dsc_pub, tbs_actual_len)
    };

    build_sod_from_tbs(dg1, dsc_priv, dsc_pub, csca_priv, tbs_bytes)
}

/// Build a TBS certificate with an extra padding extension to reach the target
/// size.
fn build_padded_tbs_certificate_bytes(dsc_pub: &RsaPublicKey, target_len: usize) -> Vec<u8> {
    use rasn_pkix::{
        Extension, SubjectPublicKeyInfo as RasnSpki, TbsCertificate as RasnTbs, Validity, Version,
    };

    let null_params = der::encode(&()).expect("encode NULL");

    let spki = RasnSpki {
        algorithm:          AlgorithmIdentifier {
            algorithm:  oid_rsa_encryption(),
            parameters: Some(Any::new(null_params.clone())),
        },
        subject_public_key: BitString::from_vec(
            dsc_pub.to_pkcs1_der().expect("pkcs1 der").to_vec(),
        ),
    };

    let now = chrono::Utc::now();
    let five_years_secs: i64 = 5 * 365 * 24 * 60 * 60;
    let not_before_dt =
        chrono::DateTime::from_timestamp(now.timestamp() - five_years_secs, 0).expect("valid");
    let not_after_dt =
        chrono::DateTime::from_timestamp(now.timestamp() + five_years_secs, 0).expect("valid");

    // Start with base extensions
    let extensions = build_dsc_extensions(dsc_pub);

    // Build once without padding to measure base size
    let base_tbs = RasnTbs {
        version:                 Version::V3,
        serial_number:           Integer::from(2),
        signature:               AlgorithmIdentifier {
            algorithm:  oid_sha256_with_rsa(),
            parameters: Some(Any::new(null_params.clone())),
        },
        issuer:                  build_dn("Mock CSCA", "UT", "Mock Passport Authority"),
        validity:                Validity {
            not_before: rasn_pkix::Time::Utc(not_before_dt),
            not_after:  rasn_pkix::Time::Utc(not_after_dt),
        },
        subject:                 build_dn("Mock DSC", "UT", "Mock Passport Authority"),
        subject_public_key_info: spki.clone(),
        issuer_unique_id:        None,
        subject_unique_id:       None,
        extensions:              Some(extensions.clone()),
    };
    let base_encoded = der::encode(&base_tbs).expect("encode base TBS");
    let base_len = base_encoded.len();

    if base_len >= target_len {
        return base_encoded;
    }

    // Helper closure to build a TBS with given extensions
    let build_tbs = |exts: rasn_pkix::Extensions| -> Vec<u8> {
        let tbs = RasnTbs {
            version:                 Version::V3,
            serial_number:           Integer::from(2),
            signature:               AlgorithmIdentifier {
                algorithm:  oid_sha256_with_rsa(),
                parameters: Some(Any::new(null_params.clone())),
            },
            issuer:                  build_dn("Mock CSCA", "UT", "Mock Passport Authority"),
            validity:                Validity {
                not_before: rasn_pkix::Time::Utc(not_before_dt),
                not_after:  rasn_pkix::Time::Utc(not_after_dt),
            },
            subject:                 build_dn("Mock DSC", "UT", "Mock Passport Authority"),
            subject_public_key_info: spki.clone(),
            issuer_unique_id:        None,
            subject_unique_id:       None,
            extensions:              Some(exts),
        };
        der::encode(&tbs).expect("encode padded TBS")
    };

    // Use a private-use OID for the padding extension: 1.3.6.1.4.1.99999.1
    let padding_oid = ObjectIdentifier::new_unchecked(vec![1, 3, 6, 1, 4, 1, 99999, 1].into());

    // Use a small, bounded number of iterations to converge on the target length.
    // DER encoding can cause non-linear changes in size due to length fields, so we
    // iteratively adjust the padding. Five iterations is
    // enough to converge in nearly all cases.
    const PADDING_ADJUSTMENT_ATTEMPTS: usize = 5;
    let mut padding_size = target_len.saturating_sub(base_len);
    for _ in 0..PADDING_ADJUSTMENT_ATTEMPTS {
        let padding_data = vec![0x42u8; padding_size];
        let padding_ext = Extension {
            extn_id:    padding_oid.clone(),
            critical:   false,
            extn_value: OctetString::from(padding_data),
        };

        let mut exts: Vec<Extension> = extensions.to_vec();
        exts.push(padding_ext);

        let encoded = build_tbs(exts.into());
        if encoded.len() == target_len {
            return encoded;
        } else if encoded.len() > target_len {
            padding_size -= encoded.len() - target_len;
        } else {
            padding_size += target_len - encoded.len();
        }
    }

    // Final attempt with current padding_size
    let padding_data = vec![0x42u8; padding_size];
    let padding_ext = Extension {
        extn_id:    padding_oid,
        critical:   false,
        extn_value: OctetString::from(padding_data),
    };
    let mut final_exts: Vec<Extension> = extensions.to_vec();
    final_exts.push(padding_ext);

    build_tbs(final_exts.into())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64},
            PassportReader, SaveToml,
        },
        base64::{engine::general_purpose::STANDARD, Engine as _},
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
        use crate::{MerkleAge720Config, MerkleAgeBaseConfig};

        let csca_priv = load_csca_mock_private_key();
        let csca_pub = csca_priv.to_public_key();
        let dsc_priv = load_dsc_mock_private_key();
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
            .expect("to merkle age 720 inputs");

        // Verify the inputs can be saved (exercises TOML serialization)
        inputs
            .add_dsc
            .save_to_toml_file("/dev/null")
            .expect("save add_dsc toml");
    }

    #[test]
    fn test_dg1_has_proper_asn1_header() {
        let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
        assert_eq!(dg1.len(), MAX_DG1_SIZE);
        // ASN.1 tag prefix
        assert_eq!(&dg1[0..5], &[0x61, 0x5b, 0x5f, 0x1f, 0x58]);
        // Document type
        assert_eq!(&dg1[5..7], b"P<");
        // Issuing country
        assert_eq!(&dg1[7..10], b"UTO");
        // Birthdate at correct offset (5 + 57 = 62)
        assert_eq!(&dg1[62..68], b"070101");
        // Expiry at correct offset (5 + 65 = 70)
        assert_eq!(&dg1[70..76], b"320101");
    }

    #[test]
    fn test_econtent_is_valid_der() {
        let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
        let econtent_bytes = build_econtent_bytes(&dg1);

        // Should be parseable as LDSSecurityObject
        let parsed: LDSSecurityObject =
            rasn::der::decode(&econtent_bytes).expect("should parse as LDSSecurityObject");
        assert_eq!(parsed.version, Integer::from(0));
        assert_eq!(parsed.data_group_hash_values.len(), 2);

        // DG1 hash should match
        let expected_hash = Sha256::digest(&dg1);
        let dg1_entry = parsed
            .data_group_hash_values
            .iter()
            .find(|dg| dg.data_group_number == Integer::from(1))
            .expect("DG1 entry");
        assert_eq!(
            dg1_entry.data_group_hash_value.as_ref(),
            expected_hash.as_slice()
        );
    }

    #[test]
    fn test_signed_attrs_is_valid_der() {
        use crate::parser::utils::oid_to_string;

        let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
        let econtent_bytes = build_econtent_bytes(&dg1);
        let signed_attrs_bytes = build_signed_attrs_bytes(&econtent_bytes);

        // Should be parseable as BTreeSet<Attribute>
        let parsed: BTreeSet<Attribute> =
            rasn::der::decode(&signed_attrs_bytes).expect("should parse as SET OF Attribute");
        assert_eq!(parsed.len(), 2);

        // Should contain contentType and messageDigest
        let oids: Vec<String> = parsed.iter().map(|a| oid_to_string(&a.r#type)).collect();
        assert!(
            oids.iter().any(|o| o == "1.2.840.113549.1.9.3"),
            "contentType OID not found in {:?}",
            oids
        );
        assert!(
            oids.iter().any(|o| o == "1.2.840.113549.1.9.4"),
            "messageDigest OID not found in {:?}",
            oids
        );
    }

    #[test]
    fn test_tbs_certificate_is_valid_der() {
        let dsc_priv = load_dsc_mock_private_key();
        let dsc_pub = dsc_priv.to_public_key();
        let tbs_bytes = build_tbs_certificate_bytes(&dsc_pub);

        // Should be parseable by x509-parser (needs to be wrapped in a
        // Certificate for full parsing, but the raw bytes should at least
        // be valid DER SEQUENCE)
        assert!(
            tbs_bytes.len() <= 720,
            "TBS must fit in 720 bytes, got {}",
            tbs_bytes.len()
        );
        assert!(
            tbs_bytes.len() > 200,
            "TBS should be >200 bytes for RSA-2048, got {}",
            tbs_bytes.len()
        );

        // The DSC modulus should be findable inside the TBS
        use rsa::traits::PublicKeyParts;
        let modulus_bytes = dsc_pub.n().to_bytes_be();
        let offset = tbs_bytes
            .windows(modulus_bytes.len())
            .position(|w| w == modulus_bytes.as_slice());
        assert!(
            offset.is_some(),
            "DSC modulus should be findable in TBS bytes"
        );
    }

    #[test]
    fn test_padded_tbs_reaches_target_length() {
        let csca_priv = load_csca_mock_private_key();
        let csca_pub = csca_priv.to_public_key();
        let dsc_priv = load_dsc_mock_private_key();
        let dsc_pub = dsc_priv.to_public_key();

        let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
        let sod =
            generate_sod_with_padded_tbs(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub, 850);

        let tbs_len = sod.certificate.tbs.bytes.len();
        // Should be close to 850 (within a few bytes due to DER length encoding)
        assert!(
            tbs_len >= 845 && tbs_len <= 855,
            "Padded TBS should be ~850 bytes, got {}",
            tbs_len
        );

        // Should still validate
        let reader = PassportReader {
            dg1: Binary::from_slice(&dg1),
            sod,
            mockdata: true,
            csca_pubkey: Some(csca_pub),
        };
        assert!(reader.validate().is_ok());
    }

    #[test]
    fn test_check_digit_icao() {
        // Known ICAO example: "L898902C3" -> check digit 6
        assert_eq!(compute_check_digit(b"L898902C3"), b'6');
        // Numeric only: "881112" -> check digit can be verified
        let cd = compute_check_digit(b"881112");
        assert!(cd >= b'0' && cd <= b'9');
    }

    #[test]
    fn test_size_constraints() {
        let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");

        let econtent_bytes = build_econtent_bytes(&dg1);
        assert!(econtent_bytes.len() <= MAX_ECONTENT_SIZE);

        let signed_attrs_bytes = build_signed_attrs_bytes(&econtent_bytes);
        assert!(signed_attrs_bytes.len() <= MAX_SIGNED_ATTRIBUTES_SIZE);

        let dsc_priv = load_dsc_mock_private_key();
        let dsc_pub = dsc_priv.to_public_key();
        let tbs_bytes = build_tbs_certificate_bytes(&dsc_pub);
        assert!(tbs_bytes.len() <= 720);
    }

    #[test]
    fn test_roundtrip_hash_chain_and_components() {
        use rsa::{pkcs1::DecodeRsaPublicKey, Pkcs1v15Sign, RsaPublicKey as RsaPub};

        let csca_priv = load_csca_mock_private_key();
        let csca_pub = csca_priv.to_public_key();
        let dsc_priv = load_dsc_mock_private_key();
        let dsc_pub = dsc_priv.to_public_key();

        let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
        let sod = generate_sod(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub);

        // 1. eContent bytes are valid DER-encoded LDSSecurityObject
        let econtent_bytes = sod.encap_content_info.e_content.bytes.as_bytes();
        let parsed_lds: LDSSecurityObject =
            rasn::der::decode(econtent_bytes).expect("eContent should parse as LDSSecurityObject");

        // 2. DG1 hash in LDSSecurityObject matches SHA-256(dg1)
        let dg1_hash = Sha256::digest(&dg1);
        let dg1_entry = parsed_lds
            .data_group_hash_values
            .iter()
            .find(|dg| dg.data_group_number == Integer::from(1))
            .expect("DG1 hash entry");
        assert_eq!(
            dg1_entry.data_group_hash_value.as_ref(),
            dg1_hash.as_slice(),
            "DG1 hash mismatch in eContent"
        );

        // 3. SignedAttributes bytes are valid DER-encoded SET OF Attribute
        let signed_attrs_bytes = sod.signer_info.signed_attrs.bytes.as_bytes();
        let parsed_attrs: BTreeSet<Attribute> = rasn::der::decode(signed_attrs_bytes)
            .expect("SignedAttributes should parse as SET OF Attribute");
        assert_eq!(parsed_attrs.len(), 2);

        // 4. messageDigest in SignedAttributes == SHA-256(eContent bytes)
        let econtent_hash = Sha256::digest(econtent_bytes);
        let msg_digest_attr = parsed_attrs
            .iter()
            .find(|a| {
                let oid = crate::parser::utils::oid_to_string(&a.r#type);
                oid == "1.2.840.113549.1.9.4"
            })
            .expect("messageDigest attribute");
        let msg_digest_value = msg_digest_attr.values.first().expect("digest value");
        let parsed_digest: OctetString =
            rasn::der::decode(msg_digest_value.as_bytes()).expect("parse OCTET STRING");
        assert_eq!(
            parsed_digest.as_ref(),
            econtent_hash.as_slice(),
            "eContent hash mismatch in SignedAttributes"
        );

        // 5. DSC signature over SignedAttributes verifies with DSC public key
        let dsc_pub_der = sod
            .certificate
            .tbs
            .subject_public_key_info
            .subject_public_key
            .as_bytes();
        let recovered_dsc_pub = RsaPub::from_pkcs1_der(dsc_pub_der).expect("parse DSC public key");
        let signed_attr_hash = Sha256::digest(signed_attrs_bytes);
        recovered_dsc_pub
            .verify(
                Pkcs1v15Sign::new::<Sha256>(),
                signed_attr_hash.as_slice(),
                sod.signer_info.signature.as_bytes(),
            )
            .expect("DSC signature over SignedAttributes should verify");

        // 6. CSCA signature over TBS certificate verifies with CSCA public key
        let tbs_bytes = sod.certificate.tbs.bytes.as_bytes();
        let tbs_hash = Sha256::digest(tbs_bytes);
        csca_pub
            .verify(
                Pkcs1v15Sign::new::<Sha256>(),
                tbs_hash.as_slice(),
                sod.certificate.signature.as_bytes(),
            )
            .expect("CSCA signature over TBS should verify");

        // 7. TBS bytes contain the DSC modulus at a findable offset
        use rsa::traits::PublicKeyParts;
        let modulus = dsc_pub.n().to_bytes_be();
        let offset = tbs_bytes
            .windows(modulus.len())
            .position(|w| w == modulus.as_slice());
        assert!(offset.is_some(), "DSC modulus should be findable in TBS");

        // 8. DG1 hash is findable in eContent bytes
        let dg1_hash_offset = econtent_bytes
            .windows(dg1_hash.len())
            .position(|w| w == dg1_hash.as_slice());
        assert!(
            dg1_hash_offset.is_some(),
            "DG1 hash should be findable in eContent bytes"
        );

        // 9. eContent hash is findable in SignedAttributes bytes
        let econtent_hash_offset = signed_attrs_bytes
            .windows(econtent_hash.len())
            .position(|w| w == econtent_hash.as_slice());
        assert!(
            econtent_hash_offset.is_some(),
            "eContent hash should be findable in SignedAttributes bytes"
        );
    }
}
