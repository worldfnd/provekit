use {
    crate::parser::binary::Binary,
    chrono::{DateTime, Utc},
    rasn::{
        types::{Integer, OctetString, PrintableString, SequenceOf},
        AsnType, Decode, Encode,
    },
    rasn_pkix::AlgorithmIdentifier,
    std::collections::HashMap,
    thiserror::Error,
};

pub const MAX_SIGNED_ATTRIBUTES_SIZE: usize = 220;
pub const MAX_DG1_SIZE: usize = 95;
pub const MAX_ECONTENT_SIZE: usize = 700;
pub const TREE_DEPTH: usize = 24;

/// Valid TBS certificate sizes for the new passport/ circuits.
pub const TBS_SIZES: [usize; 4] = [700, 1000, 1200, 1600];

/// RSA key sizes supported by the new passport/ circuits (CSCA and DSC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyBits {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Rsa6144,
}

impl RsaKeyBits {
    /// Key size in bytes (modulus length).
    pub fn byte_len(self) -> usize {
        match self {
            Self::Rsa1024 => 128,
            Self::Rsa2048 => 256,
            Self::Rsa3072 => 384,
            Self::Rsa4096 => 512,
            Self::Rsa6144 => 768,
        }
    }

    /// Key size in bits.
    pub fn bit_len(self) -> usize {
        match self {
            Self::Rsa1024 => 1024,
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::Rsa6144 => 6144,
        }
    }

    /// Parse from a string like "1024", "2048", etc.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "1024" => Some(Self::Rsa1024),
            "2048" => Some(Self::Rsa2048),
            "3072" => Some(Self::Rsa3072),
            "4096" => Some(Self::Rsa4096),
            "6144" => Some(Self::Rsa6144),
            _ => None,
        }
    }
}

impl std::fmt::Display for RsaKeyBits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.bit_len())
    }
}

/// RSA padding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    Pkcs1,
    Pss,
}

impl RsaPadding {
    /// Circuit path segment for this padding scheme.
    pub fn circuit_path(self) -> &'static str {
        match self {
            Self::Pkcs1 => "pkcs",
            Self::Pss => "pss",
        }
    }

    /// Parse from a string like "pkcs", "pss".
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pkcs" | "pkcs1" => Some(Self::Pkcs1),
            "pss" => Some(Self::Pss),
            _ => None,
        }
    }
}

impl std::fmt::Display for RsaPadding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.circuit_path())
    }
}

#[derive(Debug, Clone)]
pub enum DigestAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl DigestAlgorithm {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_uppercase().as_str() {
            "SHA1" | "SHA-1" => Some(Self::SHA1),
            "SHA224" | "SHA-224" => Some(Self::SHA224),
            "SHA256" | "SHA-256" => Some(Self::SHA256),
            "SHA384" | "SHA-384" => Some(Self::SHA384),
            "SHA512" | "SHA-512" => Some(Self::SHA512),
            _ => None,
        }
    }

    /// Circuit path segment for this digest algorithm (e.g. "sha256").
    pub fn circuit_path(&self) -> &'static str {
        match self {
            Self::SHA1 => "sha1",
            Self::SHA224 => "sha224",
            Self::SHA256 => "sha256",
            Self::SHA384 => "sha384",
            Self::SHA512 => "sha512",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DataGroupHashValues {
    pub values: HashMap<u32, Binary>,
}

#[derive(Debug, Clone)]
pub struct EContent {
    pub version:                u32,
    pub hash_algorithm:         DigestAlgorithm,
    pub data_group_hash_values: DataGroupHashValues,
    pub bytes:                  Binary,
}

#[derive(Debug, Clone)]
pub struct EncapContentInfo {
    pub e_content_type: String,
    pub e_content:      EContent,
}

#[derive(Debug, Clone)]
pub struct SignerInfo {
    pub version:             u32,
    pub signed_attrs:        SignedAttrs,
    pub digest_algorithm:    DigestAlgorithm,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature:           Binary,
    pub sid:                 SignerIdentifier,
}

#[derive(Debug, Clone)]
pub struct SignedAttrs {
    pub content_type:   String,
    pub message_digest: Binary,
    pub signing_time:   Option<DateTime<Utc>>,
    pub bytes:          Binary,
}

#[derive(Debug, Clone)]
pub struct SignerIdentifier {
    pub issuer_and_serial_number: Option<IssuerAndSerialNumber>,
    pub subject_key_identifier:   Option<String>,
}

#[derive(Debug, Clone)]
pub struct IssuerAndSerialNumber {
    pub issuer:        String,
    pub serial_number: Binary,
}

#[derive(Debug, Clone)]
pub struct SignatureAlgorithm {
    pub name:       SignatureAlgorithmName,
    pub parameters: Option<Binary>,
}

#[derive(Debug, Clone)]
pub enum SignatureAlgorithmName {
    Sha1WithRsaSignature,
    Sha256WithRsaEncryption,
    Sha384WithRsaEncryption,
    Sha512WithRsaEncryption,
    RsassaPss,
    EcdsaWithSha1,
    EcdsaWithSha256,
    EcdsaWithSha384,
    EcdsaWithSha512,
    RsaEncryption,
    EcPublicKey,
}

impl SignatureAlgorithmName {
    pub fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            "1.2.840.113549.1.1.5" => Some(Self::Sha1WithRsaSignature),
            "1.2.840.113549.1.1.11" => Some(Self::Sha256WithRsaEncryption),
            "1.2.840.113549.1.1.12" => Some(Self::Sha384WithRsaEncryption),
            "1.2.840.113549.1.1.13" => Some(Self::Sha512WithRsaEncryption),
            "1.2.840.113549.1.1.10" => Some(Self::RsassaPss),
            "1.2.840.10045.4.1" => Some(Self::EcdsaWithSha1),
            "1.2.840.10045.4.3.2" => Some(Self::EcdsaWithSha256),
            "1.2.840.10045.4.3.3" => Some(Self::EcdsaWithSha384),
            "1.2.840.10045.4.3.4" => Some(Self::EcdsaWithSha512),
            "1.2.840.113549.1.1.1" => Some(Self::RsaEncryption),
            "1.2.840.10045.2.1" => Some(Self::EcPublicKey),
            _ => None,
        }
    }
}

/// DataGroupNumber ::= INTEGER (1..16)
pub type DataGroupNumber = Integer;

/// DataGroupHash ::= SEQUENCE {
///   dataGroupNumber DataGroupNumber,
///   dataGroupHashValue OCTET STRING
/// }
#[derive(Debug, Clone, AsnType, Decode, Encode)]
pub struct DataGroupHash {
    pub data_group_number:     DataGroupNumber,
    pub data_group_hash_value: OctetString,
}

/// LDSVersionInfo ::= SEQUENCE {
///   ldsVersion PrintableString,
///   unicodeVersion PrintableString
/// }
#[derive(Debug, Clone, AsnType, Decode, Encode)]
pub struct LDSVersionInfo {
    pub lds_version:     PrintableString,
    pub unicode_version: PrintableString,
}

/// LDSSecurityObject ::= SEQUENCE {
///   version INTEGER { v0(0), v1(1), v2(2) },
///   hashAlgorithm DigestAlgorithmIdentifier,
///   dataGroupHashValues SEQUENCE SIZE (2..ub-DataGroups) OF DataGroupHash,
///   ldsVersionInfo LDSVersionInfo OPTIONAL
/// }
#[derive(Debug, Clone, AsnType, Decode, Encode)]
pub struct LDSSecurityObject {
    pub version:                Integer,
    pub hash_algorithm:         AlgorithmIdentifier,
    pub data_group_hash_values: SequenceOf<DataGroupHash>,
    pub lds_version_info:       Option<LDSVersionInfo>,
}

#[derive(Debug, Error)]
pub enum PassportError {
    #[error("DG1 hash mismatch in eContent")]
    Dg1HashMismatch,
    #[error("eContent hash mismatch in SignedAttributes")]
    EcontentHashMismatch,
    #[error("Invalid DSC public key")]
    InvalidDscKey,
    #[error("DSC signature verification failed")]
    DscSignatureInvalid,
    #[error("Failed to load CSCA keys")]
    CscaKeysMissing,
    #[error("No USA CSCA keys found")]
    NoUsaCsca,
    #[error("CSCA signature verification failed")]
    CscaSignatureInvalid,
    #[error("DSC Public key invalid")]
    DscPublicKeyInvalid,
    #[error("CSCA Public key invalid")]
    CscaPublicKeyInvalid,
    #[error("Data too large for buffer: {0}")]
    BufferOverflow(String),
    #[error("RSA exponent too large")]
    RsaExponentTooLarge,
    #[error("Required data not found: {0}")]
    DataNotFound(String),
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("CMS parsing failed: {0}")]
    CmsParsingFailed(String),
    #[error("X.509 certificate parsing failed: {0}")]
    X509ParsingFailed(String),
    #[error("ASN.1 decoding failed: {0}")]
    Asn1DecodingFailed(String),
    #[error("Base64 decoding failed: {0}")]
    Base64DecodingFailed(String),
    #[error("Missing required field: {0}")]
    MissingRequiredField(String),
    #[error("Invalid certificate type")]
    InvalidCertificateType,
    #[error("Missing DG1 hash in eContent")]
    MissingDg1Hash,
    #[error("Missing CSCA public key for mock data")]
    MissingCscaMockKey,
    #[error("Failed to load CSCA public keys")]
    FailedToLoadCscaKeys,
    #[error("Invalid date: {0}")]
    InvalidDate(String),
    #[error("Unsupported digest algorithm: {0}")]
    UnsupportedDigestAlgorithm(String),
    #[error("Invalid hex field '{field}': {source}")]
    InvalidHexField {
        field:  String,
        source: hex::FromHexError,
    },
    #[error("Invalid leaf_index '{value}': must be a non-negative integer")]
    InvalidLeafIndex { value: String },
}
