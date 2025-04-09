//! Serde workaround to encode types as JSON strings in non-human-readable
//! formats.

use serde::{de::Error as _, ser::Error as _, Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    if serializer.is_human_readable() {
        T::serialize(obj, serializer)
    } else {
        let json = serde_json::to_string(obj).map_err(|e| S::Error::custom(e))?;
        serializer.serialize_str(&json)
    }
}

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        T::deserialize(deserializer)
    } else {
        let json: &str = <&str>::deserialize(deserializer)?;
        serde_json::from_str(json).map_err(|e| D::Error::custom(e))
    }
}
