use {
    crate::parser::binary::Binary,
    serde::Deserialize,
    std::{cell::RefCell, collections::HashMap, fs},
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
    // pub subject:    String,
    #[serde(rename = "notBefore")]
    pub not_before: String,
    #[serde(rename = "notAfter")]
    pub not_after:  String,
    pub serial:     String,
}

thread_local! {
    static CSCA_JSON_PATH: RefCell<Option<String>> = RefCell::new(None);
}

pub fn set_csca_json_path(path: Option<String>) {
    CSCA_JSON_PATH.with(|p| *p.borrow_mut() = path);
}

pub fn load_csca_public_keys() -> Result<HashMap<String, Vec<CscaKey>>, Box<dyn std::error::Error>>
{
    let path = CSCA_JSON_PATH
        .with(|p| p.borrow().clone())
        .unwrap_or_else(|| "csca_registry/csca_public_key.json".to_string());
    let file_content = fs::read_to_string(path)?;
    let csca_keys: HashMap<String, Vec<CscaKey>> = serde_json::from_str(&file_content)?;
    Ok(csca_keys)
}

pub fn to_fixed_array<const N: usize>(bytes: Vec<u8>, label: &str) -> [u8; N] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{label} not {N} bytes"))
}

pub fn to_u32(bytes: Vec<u8>) -> u32 {
    if bytes.len() > 4 {
        panic!("RSA exponent too large");
    }
    let mut buf = [0u8; 4];
    buf[4 - bytes.len()..].copy_from_slice(&bytes);
    u32::from_be_bytes(buf)
}

pub fn find_offset(haystack: &[u8], needle: &[u8], label: &str) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| panic!("{label} not found"))
}
