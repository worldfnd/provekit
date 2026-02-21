//! Serde workaround to encode `Vec<u8>` as base64 strings in
//! human-readable formats.
//!
//! Uses standard base64 encoding (33% overhead) instead of hexadecimal
//! (100% overhead), cutting human-readable proof size by ~25%.
//! Deserialization auto-detects hex for backwards compatibility.

use {
    base64::{engine::general_purpose::STANDARD, Engine as _},
    serde::{de::Error as _, Deserialize, Deserializer, Serializer},
};

pub fn serialize<S>(obj: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        let b64 = STANDARD.encode(obj);
        serializer.serialize_str(&b64)
    } else {
        serializer.serialize_bytes(obj)
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let encoded: String = <String>::deserialize(deserializer)?;
        if encoded.len() % 2 == 0 && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(&encoded).map_err(D::Error::custom)
        } else {
            STANDARD.decode(&encoded).map_err(D::Error::custom)
        }
    } else {
        <Vec<u8>>::deserialize(deserializer)
    }
}
