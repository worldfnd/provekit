use {
    crate::parser::binary::Binary,
    serde::Deserialize,
    std::{collections::HashMap, fs},
};

#[derive(Debug)]
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

pub fn fit<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut buf = [0u8; N];
    let len = data.len().min(N);
    buf[..len].copy_from_slice(&data[..len]);
    buf
}

#[derive(Deserialize)]
pub struct CscaKey {
    pub filename:   String,
    pub public_key: String,
    // pub modulus:    String,
    // pub exponent:   u32,
    // pub subject:    String,
    // #[serde(rename = "notBefore")]
    // pub not_before: String,
    // #[serde(rename = "notAfter")]
    // pub not_after:  String,
    // pub serial:     String,
}

pub fn load_csca_public_keys() -> Result<HashMap<String, Vec<CscaKey>>, Box<dyn std::error::Error>>
{
    let file_content = fs::read_to_string("csca_registry/csca_public_key.json")?;
    let csca_keys: HashMap<String, Vec<CscaKey>> = serde_json::from_str(&file_content)?;
    Ok(csca_keys)
}
