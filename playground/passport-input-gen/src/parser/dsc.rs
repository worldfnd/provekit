use {
    crate::parser::{
        binary::Binary,
        oid_registry::REGISTRY,
        types::{PassportError, SignatureAlgorithm, SignatureAlgorithmName},
        utils::{get_oid_name, strip_length_prefix, OidEntry},
    },
    chrono::{DateTime, Utc},
    std::collections::HashMap,
    x509_parser::{parse_x509_certificate, prelude::X509Certificate, x509::X509Name},
};

#[derive(Debug, Clone)]
pub struct TbsCertificate {
    pub version:                 u32,
    pub serial_number:           Binary,
    pub signature_algorithm:     SignatureAlgorithm,
    pub issuer:                  String,
    pub validity_not_before:     DateTime<Utc>,
    pub validity_not_after:      DateTime<Utc>,
    pub subject:                 String,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub issuer_unique_id:        Option<Binary>,
    pub subject_unique_id:       Option<Binary>,
    pub extensions:              HashMap<String, (bool, Binary)>,
    pub bytes:                   Binary,
}

#[derive(Debug, Clone)]
pub struct SubjectPublicKeyInfo {
    pub signature_algorithm: SignatureAlgorithm,
    pub subject_public_key:  Binary,
}

#[derive(Debug, Clone)]
pub struct DSC {
    pub tbs:                 TbsCertificate,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature:           Binary,
}

impl DSC {
    /// Formats an X.509 Distinguished Name (DN) into a readable string.
    fn format_name(name: &X509Name<'_>, registry: &HashMap<&'static str, OidEntry>) -> String {
        name.iter_rdn()
            .map(|rdn| {
                rdn.iter()
                    .map(|attr| {
                        let oid_str = attr.attr_type().to_string();
                        let field_name = get_oid_name(&oid_str, registry);
                        let value = attr
                            .as_str()
                            .map(String::from)
                            .unwrap_or_else(|_| hex::encode(attr.as_slice()));
                        format!("{}={}", field_name, value)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Parses a DER-encoded X.509 certificate into a `DSC`.
    pub fn from_der(binary: &Binary) -> Result<DSC, PassportError> {
        let der = strip_length_prefix(binary);
        let (_, cert) = parse_x509_certificate(&der.data).expect("X509 decode failed");
        Self::from_x509(cert)
    }

    /// Converts a parsed `X509Certificate` into the internal `DSC` struct.
    fn from_x509(cert: X509Certificate<'_>) -> Result<DSC, PassportError> {
        let tbs = cert.tbs_certificate;
        let tbs_bytes = Binary::from_slice(tbs.as_ref());

        let not_before = tbs.validity.not_before.to_datetime();
        let not_before_utc =
            DateTime::<Utc>::from_timestamp(not_before.unix_timestamp(), not_before.nanosecond())
                .ok_or_else(|| PassportError::InvalidDate("Invalid not_before time".to_string()))?;

        let not_after = tbs.validity.not_after.to_datetime();
        let not_after_utc =
            DateTime::<Utc>::from_timestamp(not_after.unix_timestamp(), not_after.nanosecond())
                .ok_or_else(|| PassportError::InvalidDate("Invalid not_after time".to_string()))?;

        // Helper function to create SignatureAlgorithm from AlgorithmIdentifier
        let create_signature_algorithm = |alg_id: &x509_parser::x509::AlgorithmIdentifier<'_>| -> Result<SignatureAlgorithm, PassportError> {
            let name = SignatureAlgorithmName::from_oid(&alg_id.algorithm.to_string()).ok_or_else(
                || PassportError::UnsupportedSignatureAlgorithm(alg_id.algorithm.to_string()),
            )?;
            let parameters = alg_id
                .parameters
                .as_ref()
                .map(|p| Binary::from_slice(p.data));
            Ok(SignatureAlgorithm { name, parameters })
        };

        let tbs_signature_algorithm = create_signature_algorithm(&tbs.signature)?;
        let cert_signature_algorithm = create_signature_algorithm(&cert.signature_algorithm)?;
        let spki_algorithm = create_signature_algorithm(&tbs.subject_pki.algorithm)?;

        let subject_public_key_info = SubjectPublicKeyInfo {
            signature_algorithm: spki_algorithm,
            subject_public_key:  Binary::from_slice(&tbs.subject_pki.subject_public_key.data),
        };

        let mut extensions = HashMap::new();
        for ext in tbs.extensions() {
            let oid_str = ext.oid.to_string();
            let name = get_oid_name(&oid_str, &REGISTRY);
            extensions.insert(name, (ext.critical, Binary::from_slice(ext.value)));
        }

        let tbs_struct = TbsCertificate {
            version: tbs.version().0,
            serial_number: Binary::from_slice(tbs.raw_serial()),
            signature_algorithm: tbs_signature_algorithm,
            issuer: Self::format_name(&tbs.issuer, &REGISTRY),
            validity_not_before: not_before_utc,
            validity_not_after: not_after_utc,
            subject: Self::format_name(&tbs.subject, &REGISTRY),
            subject_public_key_info,
            issuer_unique_id: tbs
                .issuer_uid
                .as_ref()
                .map(|uid| Binary::from_slice(uid.0.as_ref())),
            subject_unique_id: tbs
                .subject_uid
                .as_ref()
                .map(|uid| Binary::from_slice(uid.0.as_ref())),
            extensions,
            bytes: tbs_bytes,
        };

        Ok(DSC {
            tbs:                 tbs_struct,
            signature_algorithm: cert_signature_algorithm,
            signature:           Binary::from_slice(&cert.signature_value.data),
        })
    }
}
