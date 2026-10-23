//! Serde workaround to encode types as CBOR bytes in non-human readable
//! formats.
//!
//! Internally tagged enums are not compatible with schemaless formats like
//! Postcard, so we embed them as self describing CBOR

use serde::{
    de::{DeserializeOwned, Error as _},
    ser::Error as _,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// Max CBOR nesting depth, matching what `serde_json` accepts by default
pub const RECURSION_LIMIT: usize = 127;

pub fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    if serializer.is_human_readable() {
        T::serialize(obj, serializer)
    } else {
        let mut cbor = Vec::new();
        ciborium::into_writer(obj, &mut cbor)
            .map_err(|e| S::Error::custom(format!("while serializing CBOR: {e}")))?;
        serializer.serialize_bytes(&cbor)
    }
}

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        T::deserialize(deserializer)
    } else {
        let cbor = <Vec<u8>>::deserialize(deserializer)?;
        let mut reader = cbor.as_slice();
        let obj = ciborium::de::from_reader_with_recursion_limit(&mut reader, RECURSION_LIMIT)
            .map_err(|e| D::Error::custom(format!("while deserializing CBOR: {e}")))?;
        if reader.is_empty() {
            Ok(obj)
        } else {
            Err(D::Error::custom("while deserializing CBOR: trailing bytes"))
        }
    }
}
