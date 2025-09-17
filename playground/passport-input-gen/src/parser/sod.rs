use {
    crate::parser::{
        binary::Binary,
        dsc::DSC,
        oid_registry::REGISTRY,
        types::{
            DataGroupHashValues, DigestAlgorithm, EContent, EncapContentInfo,
            IssuerAndSerialNumber, LDSSecurityObject, PassportError, SignatureAlgorithm,
            SignatureAlgorithmName, SignedAttrs, SignerIdentifier, SignerInfo,
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
    /// Parses the `signedAttrs` field from a `SignerInfo`.
    fn parse_signed_attrs(
        signer_info_raw: &rasn_cms::SignerInfo,
        registry: &HashMap<&'static str, OidEntry>,
    ) -> Result<SignedAttrs, PassportError> {
        let mut signed_attr_map: HashMap<String, Binary> = HashMap::new();
        let mut reconstructed_signed_attrs: Vec<Attribute> = Vec::new();

        let attrs =
            signer_info_raw
                .signed_attrs
                .as_ref()
                .ok_or(PassportError::MissingRequiredField(
                    "signedAttrs".to_string(),
                ))?;

        for attr in attrs {
            let oid_str = oid_to_string(&attr.r#type);
            let name = get_oid_name(&oid_str, registry);
            let val = attr
                .values
                .first()
                .ok_or(PassportError::DataNotFound(format!(
                    "No value in attribute with OID: {}",
                    oid_str
                )))?
                .as_bytes();
            signed_attr_map.insert(name, Binary::from_slice(val));
            reconstructed_signed_attrs.push(attr.clone());
        }

        let signed_attrs_set = BTreeSet::from_iter(reconstructed_signed_attrs);
        let reconstructed_block = der::encode(&signed_attrs_set)
            .map_err(|e| PassportError::Asn1DecodingFailed(e.to_string()))?;

        let message_digest = signed_attr_map
            .get("messageDigest")
            .ok_or(PassportError::MissingRequiredField(
                "messageDigest".to_string(),
            ))?
            .clone();

        let signing_time = signed_attr_map
            .get("signingTime")
            .map(|time_attr| {
                der::decode::<rasn::types::UtcTime>(&time_attr.data)
                    .map_err(|e| PassportError::Asn1DecodingFailed(e.to_string()))
            })
            .transpose()?;

        let content_type_bytes =
            signed_attr_map
                .get("contentType")
                .ok_or(PassportError::MissingRequiredField(
                    "contentType".to_string(),
                ))?;

        let content_type_oid: rasn::types::ObjectIdentifier = der::decode(&content_type_bytes.data)
            .map_err(|e| PassportError::Asn1DecodingFailed(e.to_string()))?;
        let oid_string = oid_to_string(&content_type_oid);

        Ok(SignedAttrs {
            bytes: Binary::from_slice(&reconstructed_block),
            content_type: get_oid_name(&oid_string, registry),
            message_digest,
            signing_time,
        })
    }

    /// Extracts and parses the DSC (Document Signer Certificate) from a
    /// `SignedData` structure.
    fn parse_certificate(signed_data: &SignedData) -> Result<DSC, PassportError> {
        let certificates =
            signed_data
                .certificates
                .as_ref()
                .ok_or(PassportError::MissingRequiredField(
                    "certificates".to_string(),
                ))?;
        if certificates.is_empty() {
            return Err(PassportError::MissingRequiredField(
                "DSC certificate".to_string(),
            ));
        }

        let dsc = certificates
            .first()
            .ok_or(PassportError::X509ParsingFailed(
                "Failed to extract X.509 Certificate".to_string(),
            ))?;

        let dsc_cert = match dsc {
            rasn_cms::CertificateChoices::Certificate(c) => c,
            _ => return Err(PassportError::InvalidCertificateType),
        };
        let dsc_der = der::encode(&**dsc_cert)
            .map_err(|e| PassportError::X509ParsingFailed(e.to_string()))?;
        let dsc_binary = Binary::from_slice(&dsc_der);
        DSC::from_der(&dsc_binary)
    }

    /// Parses the encapsulated LDS Security Object (`encapContentInfo`) from
    /// the SOD.
    fn parse_encap_content_info(
        signed_data: &SignedData,
        registry: &HashMap<&'static str, OidEntry>,
    ) -> Result<EncapContentInfo, PassportError> {
        let econtent_bytes = signed_data
            .encap_content_info
            .content
            .as_ref()
            .ok_or(PassportError::MissingRequiredField("eContent".to_string()))?;

        let econtent: LDSSecurityObject = der::decode(econtent_bytes)
            .map_err(|e| PassportError::Asn1DecodingFailed(e.to_string()))?;

        let content_type = &signed_data.encap_content_info.content_type;
        let econtent_oid = get_oid_name(&oid_to_string(content_type), registry);
        let econtent_vec = signed_data.encap_content_info.content.clone().ok_or(
            PassportError::MissingRequiredField("eContent data".to_string()),
        )?;
        let econtent_binary = Binary::from_slice(&econtent_vec);
        let hash_algorithm_oid = oid_to_string(&econtent.hash_algorithm.algorithm);
        let hash_algorithm_name = get_hash_algo_name(&hash_algorithm_oid, registry);

        let hash_algorithm = DigestAlgorithm::from_name(&hash_algorithm_name).ok_or(
            PassportError::UnsupportedDigestAlgorithm(hash_algorithm_name),
        )?;

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

        Ok(EncapContentInfo {
            e_content_type: econtent_oid,
            e_content:      EContent {
                version: version_from(&econtent.version),
                hash_algorithm,
                data_group_hash_values: data_group_hash_values_map,
                bytes: econtent_binary,
            },
        })
    }

    /// Parses a `SignerInfo` structure into a custom `SignerInfo` model.
    fn parse_signer_info(
        signer_info_raw: &rasn_cms::SignerInfo,
        registry: &HashMap<&'static str, OidEntry>,
    ) -> Result<SignerInfo, PassportError> {
        let signed_attrs = Self::parse_signed_attrs(signer_info_raw, registry)?;
        let signer_version = version_from(&signer_info_raw.version);

        let digest_oid_str = oid_to_string(&signer_info_raw.digest_algorithm.algorithm);
        let digest_name = get_oid_name(&digest_oid_str, registry);
        let signed_digest_algorithm_oid = DigestAlgorithm::from_name(&digest_name)
            .ok_or(PassportError::UnsupportedDigestAlgorithm(digest_name))?;

        let signature_algorithm_oid = oid_to_string(&signer_info_raw.signature_algorithm.algorithm);
        let signature_algorithm = SignatureAlgorithmName::from_oid(&signature_algorithm_oid)
            .ok_or(PassportError::UnsupportedSignatureAlgorithm(
                signature_algorithm_oid,
            ))?;

        let signature_parameters = signer_info_raw
            .signature_algorithm
            .parameters
            .as_ref()
            .map(|p| Binary::from_slice(p.as_bytes()));

        let signature = Binary::from_slice(&signer_info_raw.signature);
        let signer_identifier = Self::parse_signer_identifier(signer_info_raw.sid.clone());
        let signing_time = signed_attrs.signing_time.and_then(|ut| {
            let time_str = ut.to_string();
            chrono::DateTime::parse_from_rfc3339(&format!("{}T00:00:00Z", time_str))
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        });
        Ok(SignerInfo {
            version: signer_version,
            signed_attrs: SignedAttrs {
                content_type: signed_attrs.content_type,
                message_digest: signed_attrs.message_digest,
                signing_time,
                bytes: signed_attrs.bytes,
            },
            digest_algorithm: signed_digest_algorithm_oid,
            signature_algorithm: SignatureAlgorithm {
                name:       signature_algorithm,
                parameters: signature_parameters,
            },
            signature,
            sid: signer_identifier,
        })
    }

    /// Parses the signer identifier (SID) from the `SignerInfo`.
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

    /// Entry point: parses a full SOD (Security Object Document) from raw DER
    /// bytes.
    pub fn from_der(binary: &mut Binary) -> Result<SOD, PassportError> {
        *binary = strip_length_prefix(binary);
        let content_info: ContentInfo = der::decode(&binary.data)
            .map_err(|e| PassportError::CmsParsingFailed(e.to_string()))?;
        let signed_data: SignedData = der::decode(content_info.content.as_bytes())
            .map_err(|e| PassportError::CmsParsingFailed(e.to_string()))?;

        if signed_data.signer_infos.is_empty() {
            return Err(PassportError::DataNotFound(
                "No SignerInfos found".to_string(),
            ));
        }

        let signer_info_raw = signed_data
            .signer_infos
            .first()
            .ok_or(PassportError::DataNotFound(
                "No SignerInfo found".to_string(),
            ))?
            .clone();

        let digest_algorithms: Vec<DigestAlgorithm> = signed_data
            .digest_algorithms
            .iter()
            .filter_map(|alg| {
                let oid_str = oid_to_string(&alg.algorithm);
                let name = get_hash_algo_name(&oid_str, &REGISTRY);
                DigestAlgorithm::from_name(&name)
            })
            .collect();

        let certificate = Self::parse_certificate(&signed_data)?;
        let encap_content_info = Self::parse_encap_content_info(&signed_data, &REGISTRY)?;
        let signer_info = Self::parse_signer_info(&signer_info_raw, &REGISTRY)?;
        let sod_version = version_from(&signed_data.version);

        Ok(SOD {
            version: sod_version,
            digest_algorithms,
            encap_content_info,
            signer_info,
            certificate,
            bytes: binary.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_EF_SOD: &str = "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";

    fn parse_sod() -> SOD {
        let mut sod_bytes = Binary::from_base64(FIXTURE_EF_SOD).unwrap();
        SOD::from_der(&mut sod_bytes).unwrap()
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

        let expected_not_before = chrono::DateTime::parse_from_rfc3339("2013-12-16T21:43:18+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let expected_not_after = chrono::DateTime::parse_from_rfc3339("2014-12-11T21:43:18+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert_eq!(tbs.validity_not_before, expected_not_before);
        assert_eq!(tbs.validity_not_after, expected_not_after);
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
