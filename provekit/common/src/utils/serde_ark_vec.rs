use {
    crate::FieldElement,
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    serde::{
        de::{Error as _, SeqAccess, Visitor},
        ser::{Error as _, SerializeSeq},
        Deserializer, Serializer,
    },
    std::fmt,
};

pub fn serialize<S>(vec: &Vec<FieldElement>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let is_human_readable = serializer.is_human_readable();
    let mut seq = serializer.serialize_seq(Some(vec.len()))?;
    for element in vec {
        let mut buf = Vec::with_capacity(element.compressed_size());
        element
            .serialize_compressed(&mut buf)
            .map_err(|e| S::Error::custom(format!("Failed to serialize: {e}")))?;

        // Write bytes
        if is_human_readable {
            // ark_serialize doesn't have human-readable serialization. And Serde
            // doesn't have good defaults for [u8]. So we implement hexadecimal
            // serialization.
            let hex = hex::encode(buf);
            seq.serialize_element(&hex)?;
        } else {
            seq.serialize_element(&buf)?;
        }
    }
    seq.end()
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<FieldElement>, D::Error>
where
    D: Deserializer<'de>,
{
    struct VecVisitor {
        is_human_readable: bool,
    }

    impl<'de> Visitor<'de> for VecVisitor {
        type Value = Vec<FieldElement>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of field elements")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            if self.is_human_readable {
                while let Some(hex) = seq.next_element::<String>()? {
                    let bytes = hex::decode(hex)
                        .map_err(|e| A::Error::custom(format!("invalid hex: {e}")))?;
                    let mut reader = &*bytes;
                    let element = FieldElement::deserialize_compressed(&mut reader)
                        .map_err(|e| A::Error::custom(format!("deserialize failed: {e}")))?;
                    if !reader.is_empty() {
                        return Err(A::Error::custom("while deserializing: trailing bytes"));
                    }
                    vec.push(element);
                }
            } else {
                while let Some(bytes) = seq.next_element::<Vec<u8>>()? {
                    let mut reader = &*bytes;
                    let element = FieldElement::deserialize_compressed(&mut reader)
                        .map_err(|e| A::Error::custom(format!("deserialize failed: {e}")))?;
                    if !reader.is_empty() {
                        return Err(A::Error::custom("while deserializing: trailing bytes"));
                    }
                    vec.push(element);
                }
            }
            Ok(vec)
        }
    }

    let is_human_readable = deserializer.is_human_readable();
    deserializer.deserialize_seq(VecVisitor { is_human_readable })
}
