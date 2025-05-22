use {
    crate::FieldElement,
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    serde::{de::Error as _, ser::Error as _, Deserialize as _, Deserializer, Serializer},
};

pub fn serialize<S>(obj: &Option<FieldElement>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match obj {
        Some(value) => {
            let mut buf = Vec::with_capacity(value.compressed_size());
            value
                .serialize_compressed(&mut buf)
                .map_err(|e| S::Error::custom(format!("Failed to serialize: {e}")))?;

            // Write bytes
            if serializer.is_human_readable() {
                // ark_serialize doesn't have human-readable serialization. And Serde
                // doesn't have good defaults for [u8]. So we implement hexadecimal
                // serialization.
                let hex = hex::encode(buf);
                serializer.serialize_some(&hex)
            } else {
                serializer.serialize_some(&buf)
            }
        }
        None => serializer.serialize_none(),
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<FieldElement>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let maybe_hex: Option<String> = Option::deserialize(deserializer)?;
        match maybe_hex {
            Some(hex) => {
                let bytes =
                    hex::decode(&hex).map_err(|e| D::Error::custom(format!("invalid hex: {e}")))?;
                let mut reader = &*bytes;
                let field = FieldElement::deserialize_compressed(&mut reader)
                    .map_err(|e| D::Error::custom(format!("deserialize failed: {e}")))?;
                Ok(Some(field))
            }
            None => Ok(None),
        }
    } else {
        let maybe_bytes: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match maybe_bytes {
            Some(bytes) => {
                let mut reader = &*bytes;
                let field = FieldElement::deserialize_compressed(&mut reader)
                    .map_err(|e| D::Error::custom(format!("deserialize failed: {e}")))?;
                Ok(Some(field))
            }
            None => Ok(None),
        }
    }
}
