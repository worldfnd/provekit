use {crate::parser::binary::Binary, std::collections::HashMap};

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
