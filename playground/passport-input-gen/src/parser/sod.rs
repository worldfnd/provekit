use {
    crate::parser::{
        binary::Binary,
        dsc::DSC,
        oid_registry::load_oids,
        types::{
            DataGroupHashValues, DigestAlgorithm, EContent, EncapContentInfo,
            IssuerAndSerialNumber, LDSSecurityObject, SignatureAlgorithm, SignatureAlgorithmName,
            SignedAttrs, SignerIdentifier, SignerInfo,
        },
        utils::{
            get_hash_algo_name, get_oid_name, oid_to_string, strip_length_prefix, version_from,
            OidEntry,
        },
    },
    rasn::der,
    rasn_cms::{Attribute, ContentInfo, SignedData},
    std::collections::{BTreeSet, HashMap},
};

#[derive(Debug, Clone)]
pub struct SOD {
    pub version:            u32,
    pub digest_algorithms:  Vec<DigestAlgorithm>,
    pub encap_content_info: EncapContentInfo,
    pub signer_info:        SignerInfo,
    pub certificate:        DSC,
    pub bytes:              Binary,
}

impl SOD {
    fn parse_signed_attrs(
        signer_info_raw: &rasn_cms::SignerInfo,
        registry: &HashMap<&'static str, OidEntry>,
    ) -> SignedAttrs {
        let mut signed_attr_map: HashMap<String, Binary> = HashMap::new();
        let mut reconstructed_signed_attrs: Vec<Attribute> = vec![];

        for attr in signer_info_raw.signed_attrs.clone().unwrap_or_default() {
            let oid: &rasn::types::ObjectIdentifier = &attr.r#type;
            let values = &attr.values;
            let oid_str = oid_to_string(oid);

            let name = get_oid_name(&oid_str, registry);
            let val = values.first().expect("No value in Attribute").as_bytes();
            signed_attr_map.insert(name, Binary::from_slice(val));

            reconstructed_signed_attrs.push(attr);
        }

        let signed_attrs_set = BTreeSet::from_iter(reconstructed_signed_attrs);
        let reconstructed_block =
            der::encode(&signed_attrs_set).expect("Failed to encode reconstructed signedAttrs");

        let message_digest = signed_attr_map
            .get("messageDigest")
            .expect("No messageDigest found")
            .clone();

        let signing_time = signed_attr_map.get("signingTime").map(|time_attr| {
            der::decode::<rasn::types::UtcTime>(&time_attr.data)
                .expect("Failed to decode signingTime")
        });

        let content_type_bytes = signed_attr_map
            .get("contentType")
            .expect("No ContentType found in the map");

        let content_type_oid: rasn::types::ObjectIdentifier =
            der::decode(&content_type_bytes.data).expect("Failed to decode contentType OID");

        let oid_string: String = oid_to_string(&content_type_oid);

        SignedAttrs {
            bytes: Binary::from_slice(&reconstructed_block),
            content_type: get_oid_name(&oid_string, registry),
            message_digest,
            signing_time,
        }
    }

    fn parse_certificate(signed_data: &SignedData) -> DSC {
        let certificates = signed_data
            .certificates
            .as_ref()
            .expect("No certificates field in SOD");
        if certificates.is_empty() {
            panic!("No DSC certificate found in SOD");
        }
        if certificates.len() > 1 {
            eprintln!("Warning: Found multiple DSC certificates");
        }

        let dsc = certificates
            .first()
            .expect("Failed to extract X.509 Certificate");

        let dsc_cert = match dsc {
            rasn_cms::CertificateChoices::Certificate(c) => c,
            _ => panic!("Unsupported certificate type"),
        };
        let dsc_der = der::encode(&**dsc_cert).expect("Failed to encode DSC certificate");
        let dsc_binary = Binary::from_slice(&dsc_der);
        DSC::from_der(&dsc_binary)
    }

    fn parse_encap_content_info(
        signed_data: &SignedData,
        registry: &HashMap<&'static str, OidEntry>,
    ) -> EncapContentInfo {
        let econtent_bytes = signed_data
            .encap_content_info
            .content
            .as_ref()
            .expect("No eContent found");

        let econtent: LDSSecurityObject =
            der::decode(econtent_bytes).expect("Failed to decode LDS Security Object");

        let content_type = &signed_data.encap_content_info.content_type;
        let econtent_oid = get_oid_name(&oid_to_string(content_type), registry);
        let econtent_vec = signed_data.encap_content_info.content.clone().unwrap();
        let econtent_binary = Binary::from_slice(&econtent_vec);
        let hash_algorithm_oid = oid_to_string(&econtent.hash_algorithm.algorithm);
        let hash_algorithm_name = get_hash_algo_name(&hash_algorithm_oid, registry);

        let hash_algorithm = DigestAlgorithm::from_name(&hash_algorithm_name)
            .expect("Unsupported hash algorithm in eContent");
        let mut data_group_hash_values_map = DataGroupHashValues {
            values: HashMap::new(),
        };

        let mut sorted_data_groups: Vec<_> = econtent.data_group_hash_values.into_iter().collect();
        sorted_data_groups.sort_by_key(|dg| version_from(&dg.data_group_number));

        for data_group in sorted_data_groups {
            let dg_number = version_from(&data_group.data_group_number);
            let hash_value = Binary::from_slice(&data_group.data_group_hash_value);
            data_group_hash_values_map
                .values
                .insert(dg_number, hash_value);
        }

        EncapContentInfo {
            e_content_type: econtent_oid,
            e_content:      EContent {
                version: version_from(&econtent.version),
                hash_algorithm,
                data_group_hash_values: data_group_hash_values_map,
                bytes: econtent_binary,
            },
        }
    }

    fn parse_signer_info(
        signer_info_raw: &rasn_cms::SignerInfo,
        registry: &HashMap<&'static str, OidEntry>,
    ) -> SignerInfo {
        let signed_attrs = Self::parse_signed_attrs(signer_info_raw, registry);
        let signer_version = version_from(&signer_info_raw.version);

        let signed_digest_algorithm_oid = DigestAlgorithm::from_name(&get_oid_name(
            &oid_to_string(&signer_info_raw.digest_algorithm.algorithm),
            registry,
        ))
        .expect("Unsupported digest algorithm");

        let signature_algorithm_name =
            oid_to_string(&signer_info_raw.signature_algorithm.algorithm);
        let signature_algorithm = SignatureAlgorithmName::from_oid(&signature_algorithm_name)
            .expect("Unsupported signature algorithm");

        let signature_parameters = signer_info_raw
            .signature_algorithm
            .parameters
            .as_ref()
            .map(|p| Binary::from_slice(p.as_bytes()));

        let signature = Binary::from_slice(&signer_info_raw.signature);
        let signer_identifier = Self::parse_signer_identifier(signer_info_raw.sid.clone());
        SignerInfo {
            version: signer_version,
            signed_attrs: SignedAttrs {
                content_type:   signed_attrs.content_type,
                message_digest: signed_attrs.message_digest,
                signing_time:   signed_attrs.signing_time.map(|ut| {
                    let time_str = ut.to_string();
                    chrono::DateTime::parse_from_rfc3339(&format!("{}T00:00:00Z", time_str))
                        .unwrap_or_else(|_| chrono::Utc::now().into())
                        .with_timezone(&chrono::Utc)
                }),
                bytes:          signed_attrs.bytes,
            },
            digest_algorithm: signed_digest_algorithm_oid,
            signature_algorithm: SignatureAlgorithm {
                name:       signature_algorithm,
                parameters: signature_parameters,
            },
            signature,
            sid: signer_identifier,
        }
    }

    fn parse_signer_identifier(sid: rasn_cms::SignerIdentifier) -> SignerIdentifier {
        match sid {
            rasn_cms::SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial) => {
                let rasn_pkix::Name::RdnSequence(rdn_sequence) = &issuer_and_serial.issuer;
                let issuer_dn = rdn_sequence
                    .iter()
                    .flat_map(|rdn| rdn.iter())
                    .map(|attr| {
                        let oid_str = oid_to_string(&attr.r#type);
                        let value_str = std::str::from_utf8(attr.value.as_bytes())
                            .map(String::from)
                            .unwrap_or_else(|_| hex::encode(attr.value.as_bytes()));
                        let field_name = match oid_str.as_str() {
                            "2.5.4.3" => "CN",
                            "2.5.4.6" => "C",
                            "2.5.4.7" => "L",
                            "2.5.4.8" => "ST",
                            "2.5.4.9" => "STREET",
                            "2.5.4.10" => "O",
                            "2.5.4.11" => "OU",
                            _ => &oid_str,
                        };
                        format!("{}={}", field_name, value_str)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let serial_number =
                    Binary::from_slice(&issuer_and_serial.serial_number.to_bytes_be().1);
                SignerIdentifier {
                    issuer_and_serial_number: Some(IssuerAndSerialNumber {
                        issuer: issuer_dn,
                        serial_number,
                    }),
                    subject_key_identifier:   None,
                }
            }
            rasn_cms::SignerIdentifier::SubjectKeyIdentifier(ski) => SignerIdentifier {
                issuer_and_serial_number: None,
                subject_key_identifier:   Some(hex::encode(&ski)),
            },
        }
    }

    pub fn from_der(binary: &mut Binary) -> SOD {
        *binary = strip_length_prefix(binary);
        let hex_der = hex::decode(binary.to_hex().trim_start_matches("0x")).unwrap();
        let content_info: ContentInfo = der::decode(&hex_der).expect("CMS decode failed");
        let signed_data: SignedData =
            der::decode(content_info.content.as_bytes()).expect("SignedData decode failed");
        if signed_data.signer_infos.is_empty() {
            panic!("No SignerInfos found");
        }
        if signed_data.signer_infos.len() > 1 {
            eprintln!("Warning: Found multiple SignerInfos");
        }
        let signer_info_raw = signed_data
            .signer_infos
            .first()
            .expect("No SignerInfo found")
            .clone();
        if signer_info_raw.signed_attrs.is_none() {
            panic!("No signedAttrs found in SignerInfo");
        }
        let registry = load_oids();
        let mut digest_algorithms: Vec<DigestAlgorithm> = vec![];
        for alg in &signed_data.digest_algorithms {
            let oid_str = oid_to_string(&alg.algorithm);
            let name = get_hash_algo_name(&oid_str, &registry);
            if let Some(digest_alg) = DigestAlgorithm::from_name(&name) {
                digest_algorithms.push(digest_alg);
            } else {
                eprintln!("Unknown digest algorithm: {}", name);
            }
        }
        let certificate = Self::parse_certificate(&signed_data);
        let encap_content_info = Self::parse_encap_content_info(&signed_data, &registry);
        let signer_info = Self::parse_signer_info(&signer_info_raw, &registry);
        let sod_version = version_from(&signed_data.version);
        SOD {
            version: sod_version,
            digest_algorithms,
            encap_content_info,
            signer_info,
            certificate,
            bytes: binary.clone(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_EF_SOD: &str = "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";

    fn parse_sod() -> SOD {
        let mut sod_bytes = Binary::from_base64(FIXTURE_EF_SOD).unwrap();
        SOD::from_der(&mut sod_bytes)
    }

    #[test]
    fn should_parse_basic_sod_properties() {
        let sod = parse_sod();
        assert_eq!(sod.version, 3);
        assert_eq!(sod.digest_algorithms.len(), 1);
        assert!(matches!(sod.digest_algorithms[0], DigestAlgorithm::SHA256));
    }

    #[test]
    fn should_parse_econtent_data_correctly() {
        let sod = parse_sod();
        let econtent = &sod.encap_content_info.e_content;
        assert_eq!(econtent.version, 0);
        assert!(matches!(econtent.hash_algorithm, DigestAlgorithm::SHA256));
        let dg_hashes = &econtent.data_group_hash_values.values;
        assert_eq!(dg_hashes.len(), 5);
        assert_eq!(
            dg_hashes.get(&1).unwrap().to_hex(),
            "0x4170ca879fce6a22ffef1567ff88079f415c66ead250ab5f23781ac2cdbf42b6"
        );
        assert_eq!(
            dg_hashes.get(&2).unwrap().to_hex(),
            "0xa9a1b09dfd598087ab3fce4ae2ec65b1a1525bd258bfc27df4419f8a65e54745"
        );
    }

    #[test]
    fn should_parse_signer_info_correctly() {
        let sod = parse_sod();
        let signer = &sod.signer_info;
        assert_eq!(signer.version, 1);
        assert!(matches!(signer.digest_algorithm, DigestAlgorithm::SHA256));
        assert!(matches!(
            signer.signature_algorithm.name,
            SignatureAlgorithmName::RsassaPss
        ));
        assert_eq!(signer.signed_attrs.content_type, "mRTDSignatureData");
        assert_eq!(
            signer.signed_attrs.message_digest.to_hex(),
            "0x0420b46a0d05e280f398efeeebff67e78c736add15e75670b1ad4c6c534e8187b9d6"
        );
    }

    #[test]
    fn should_parse_certificate_information_correctly() {
        let sod = parse_sod();
        let cert = &sod.certificate;
        let tbs = &cert.tbs;
        assert_eq!(tbs.validity_not_before, "Dec 16 21:43:18 2013 +00:00");
        assert_eq!(tbs.validity_not_after, "Dec 11 21:43:18 2014 +00:00");
        assert_eq!(
            tbs.issuer,
            "countryName=DE, organizationName=HJP Consulting, organizationalUnitName=Country \
             Signer, commonName=HJP PB CS"
        );
        assert_eq!(
            tbs.subject,
            "countryName=DE, organizationName=HJP Consulting, organizationalUnitName=Document \
             Signer, commonName=HJP PB DS"
        );
        assert!(tbs.extensions.contains_key("keyUsage"));
        assert!(tbs.extensions.contains_key("authorityKeyIdentifier"));
        assert!(tbs.extensions.contains_key("subjectKeyIdentifier"));
        assert!(tbs.extensions.get("keyUsage").unwrap().0);
    }

    #[test]
    fn should_parse_signature_algorithms_correctly() {
        let sod = parse_sod();
        let cert = &sod.certificate;
        assert!(matches!(
            cert.signature_algorithm.name,
            SignatureAlgorithmName::RsassaPss
        ));
        assert!(matches!(
            cert.tbs.subject_public_key_info.signature_algorithm.name,
            SignatureAlgorithmName::RsaEncryption
        ));
        assert!(!cert.signature.is_empty());
        assert!(!sod.signer_info.signature.is_empty());
    }
}
