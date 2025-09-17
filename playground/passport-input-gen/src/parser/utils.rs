use {
    crate::parser::{binary::Binary, types::PassportError},
    serde::Deserialize,
    std::{collections::HashMap, fs},
};

#[derive(Debug, Clone)]
pub struct OidEntry {
    pub d: &'static str,
    pub c: &'static str,
    pub w: bool,
}

pub fn get_oid_name(oid: &str, registry: &HashMap<&'static str, OidEntry>) -> String {
    if let Some(entry) = registry.get(oid) {
        entry.d.to_string()
    } else {
        oid.to_string()
    }
}

pub fn get_hash_algo_name(oid: &str, registry: &HashMap<&'static str, OidEntry>) -> String {
    if let Some(entry) = registry.get(oid) {
        entry.d.replace("-", "").to_uppercase()
    } else {
        oid.to_string()
    }
}

pub fn oid_to_string(oid: &rasn::types::ObjectIdentifier) -> String {
    oid.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

pub fn strip_length_prefix(binary: &Binary) -> Binary {
    if binary.slice(0, 2).equals(&Binary::new(vec![119, 130])) {
        binary.slice(4, binary.len())
    } else {
        binary.clone()
    }
}

pub fn version_from(value: &rasn::types::Integer) -> u32 {
    value.to_u32_digits().1.first().copied().unwrap_or(0)
}

pub fn fit<const N: usize>(data: &[u8]) -> Result<[u8; N], PassportError> {
    if data.len() > N {
        return Err(PassportError::BufferOverflow(format!(
            "data size {} exceeds buffer size {}",
            data.len(),
            N
        )));
    }
    let mut buf = [0u8; N];
    buf[..data.len()].copy_from_slice(data);
    Ok(buf)
}

#[derive(Deserialize)]
pub struct CscaKey {
    #[serde(rename = "filename")]
    pub _filename:   String,
    pub public_key:  String,
    // pub subject:    String,
    #[serde(rename = "notBefore")]
    pub _not_before: String,
    #[serde(rename = "notAfter")]
    pub _not_after:  String,
    #[serde(rename = "serial")]
    pub _serial:     String,
}

pub const ASN1_OCTET_STRING_TAG: u8 = 0x04;
pub const ASN1_HEADER_LEN: usize = 2;

pub fn load_csca_public_keys() -> Result<HashMap<String, Vec<CscaKey>>, Box<dyn std::error::Error>>
{
    let path = "csca_registry/csca_public_key.json";
    let file_content = fs::read_to_string(path)?;
    let csca_keys: HashMap<String, Vec<CscaKey>> = serde_json::from_str(&file_content)?;
    Ok(csca_keys)
}

pub fn to_fixed_array<const N: usize>(bytes: &[u8], label: &str) -> Result<[u8; N], PassportError> {
    bytes.try_into().map_err(|_| {
        PassportError::BufferOverflow(format!(
            "{label} must be exactly {N} bytes, got {}",
            bytes.len()
        ))
    })
}

pub fn to_u32(bytes: Vec<u8>) -> Result<u32, PassportError> {
    if bytes.len() > 4 {
        return Err(PassportError::RsaExponentTooLarge);
    }
    let mut buf = [0u8; 4];
    buf[4 - bytes.len()..].copy_from_slice(&bytes);
    Ok(u32::from_be_bytes(buf))
}

pub fn find_offset(haystack: &[u8], needle: &[u8], label: &str) -> Result<usize, PassportError> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .ok_or_else(|| PassportError::DataNotFound(label.to_string()))
}
