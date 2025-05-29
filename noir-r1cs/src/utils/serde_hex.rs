//! Serde workaround to encode `Vec<u8>` as hexadecimal strings in
//! human-readable formats.

use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

pub fn serialize<S>(obj: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        let hex = hex::encode(obj);
        serializer.serialize_str(&hex)
    } else {
        serializer.serialize_bytes(obj)
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let hex: String = <String>::deserialize(deserializer)?;
        hex::decode(hex).map_err(D::Error::custom)
    } else {
        <Vec<u8>>::deserialize(deserializer)
    }
}
