use {
    crate::parser::{
        binary::Binary,
        oid_registry::load_oids,
        types::{SignatureAlgorithm, SignatureAlgorithmName},
        utils::{get_oid_name, strip_length_prefix, OidEntry},
    },
    std::collections::HashMap,
    x509_parser::prelude::*,
};

#[derive(Debug, Clone)]
pub struct TbsCertificate {
    pub version:                 u32,
    pub serial_number:           Binary,
    pub signature_algorithm:     SignatureAlgorithm,
    pub issuer:                  String,
    pub validity_not_before:     String,
    pub validity_not_after:      String,
    pub subject:                 String,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub issuer_unique_id:        Option<Binary>,
    pub subject_unique_id:       Option<Binary>,
    pub extensions:              HashMap<String, (bool, Binary)>,
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
    fn format_name(name: &X509Name<'_>, registry: &HashMap<&'static str, OidEntry>) -> String {
        let mut parts = Vec::new();
        for rdn in name.iter_rdn() {
            let mut rdn_parts = Vec::new();
            for attr in rdn.iter() {
                let oid_str = attr.attr_type().to_string();
                let field_name = get_oid_name(&oid_str, registry);
                let value = attr
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| hex::encode(attr.as_slice()));
                rdn_parts.push(format!("{}={}", field_name, value));
            }
            parts.push(rdn_parts.join(", "));
        }
        parts.join(", ")
    }

    pub fn from_der(binary: &Binary) -> DSC {
        let der = strip_length_prefix(binary);
        let (_, cert) = parse_x509_certificate(&der.data).expect("X509 decode failed");
        Self::from_x509(cert)
    }

    pub fn from_x509(cert: X509Certificate<'_>) -> DSC {
        let registry = load_oids();

        let tbs = cert.tbs_certificate;
        let version = tbs.version().0;

        let serial_number = Binary::from_slice(tbs.raw_serial());

        let tbs_sig_oid = tbs.signature.algorithm.to_string();
        let tbs_sig_name = SignatureAlgorithmName::from_oid(&tbs_sig_oid)
            .expect("Unsupported signature algorithm");

        let tbs_sig_params = tbs
            .signature
            .parameters
            .as_ref()
            .map(|p| Binary::from_slice(p.data));

        let issuer = Self::format_name(&tbs.issuer, &registry);
        let subject = Self::format_name(&tbs.subject, &registry);

        let not_before = tbs.validity.not_before.to_string();
        let not_after = tbs.validity.not_after.to_string();

        let spki_alg_oid = tbs.subject_pki.algorithm.algorithm.to_string();
        let spki_alg_name = SignatureAlgorithmName::from_oid(&spki_alg_oid)
            .expect("Unsupported public key algorithm");

        let spki_alg_params = tbs
            .subject_pki
            .algorithm
            .parameters
            .as_ref()
            .map(|p| Binary::from_slice(p.data));

        let subject_public_key = Binary::from_slice(&tbs.subject_pki.subject_public_key.data);

        let subject_public_key_info = SubjectPublicKeyInfo {
            signature_algorithm: SignatureAlgorithm {
                name:       spki_alg_name,
                parameters: spki_alg_params,
            },
            subject_public_key,
        };

        let issuer_unique_id = tbs
            .issuer_uid
            .as_ref()
            .map(|uid| Binary::from_slice(uid.0.as_ref()));

        let subject_unique_id = tbs
            .subject_uid
            .as_ref()
            .map(|uid| Binary::from_slice(uid.0.as_ref()));

        let mut extensions = HashMap::new();
        for ext in tbs.extensions().iter() {
            let oid_str = ext.oid.to_string();
            let name = get_oid_name(&oid_str, &registry);
            extensions.insert(name, (ext.critical, Binary::from_slice(ext.value)));
        }

        let tbs_struct = TbsCertificate {
            version,
            serial_number,
            signature_algorithm: SignatureAlgorithm {
                name:       tbs_sig_name,
                parameters: tbs_sig_params,
            },
            issuer,
            validity_not_before: not_before,
            validity_not_after: not_after,
            subject,
            subject_public_key_info,
            issuer_unique_id,
            subject_unique_id,
            extensions,
        };

        let sig_alg_oid = cert.signature_algorithm.algorithm.to_string();
        let sig_alg_name = SignatureAlgorithmName::from_oid(&sig_alg_oid)
            .expect("Unsupported signature algorithm");
        let sig_alg_params = cert
            .signature_algorithm
            .parameters
            .as_ref()
            .map(|p| Binary::from_slice(p.data));

        DSC {
            tbs:                 tbs_struct,
            signature_algorithm: SignatureAlgorithm {
                name:       sig_alg_name,
                parameters: sig_alg_params,
            },
            signature:           Binary::from_slice(&cert.signature_value.data),
        }
    }
}
