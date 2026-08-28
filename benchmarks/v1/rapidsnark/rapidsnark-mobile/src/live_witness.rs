//! Shared raw-Circom-input to WTNS helpers for native Rapidsnark benchmarks.

use {
    num_bigint::{BigInt, Sign},
    serde_json::Value,
    std::{collections::HashMap, str::FromStr},
};

pub(crate) fn parse_inputs(input_json: &str) -> HashMap<String, Vec<BigInt>> {
    fn flatten(value: &Value, output: &mut Vec<BigInt>) {
        match value {
            Value::Array(values) => values.iter().for_each(|value| flatten(value, output)),
            Value::String(value) => {
                output.push(BigInt::from_str(value).expect("Circom decimal input"))
            }
            Value::Number(value) => {
                output.push(BigInt::from_str(&value.to_string()).expect("Circom numeric input"))
            }
            _ => panic!("unsupported Circom input value: {value}"),
        }
    }

    serde_json::from_str::<Value>(input_json)
        .expect("parse Circom input JSON")
        .as_object()
        .expect("Circom inputs must be an object")
        .iter()
        .map(|(name, value)| {
            let mut values = Vec::new();
            flatten(value, &mut values);
            (name.clone(), values)
        })
        .collect()
}


/// Serialize a solved BN254 witness using the WTNS v2 format consumed by
/// Rapidsnark. Field elements are fixed-width, little-endian canonical values.
pub(crate) fn serialize_wtns(witness: &[BigInt]) -> Vec<u8> {
    const FIELD_BYTES: usize = 32;
    const BN254_SCALAR_MODULUS_LE: [u8; FIELD_BYTES] = [
        1, 0, 0, 240, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129,
        182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
    ];

    let witness_bytes = witness
        .len()
        .checked_mul(FIELD_BYTES)
        .expect("WTNS witness byte length overflow");
    let mut output = Vec::with_capacity(76 + witness_bytes);
    output.extend_from_slice(b"wtns");
    output.extend_from_slice(&2_u32.to_le_bytes());
    output.extend_from_slice(&2_u32.to_le_bytes());
    output.extend_from_slice(&1_u32.to_le_bytes());
    output.extend_from_slice(&(4_u64 + FIELD_BYTES as u64 + 4).to_le_bytes());
    output.extend_from_slice(&(FIELD_BYTES as u32).to_le_bytes());
    output.extend_from_slice(&BN254_SCALAR_MODULUS_LE);
    output.extend_from_slice(
        &u32::try_from(witness.len())
            .expect("WTNS witness count exceeds u32")
            .to_le_bytes(),
    );
    output.extend_from_slice(&2_u32.to_le_bytes());
    output.extend_from_slice(&(witness_bytes as u64).to_le_bytes());
    for value in witness {
        let (sign, bytes) = value.to_bytes_le();
        assert!(sign != Sign::Minus, "negative canonical Circom witness");
        assert!(
            bytes.len() <= FIELD_BYTES,
            "Circom witness exceeds BN254 field width"
        );
        output.extend_from_slice(&bytes);
        output.resize(output.len() + FIELD_BYTES - bytes.len(), 0);
    }
    output
}

#[cfg(test)]
mod tests {
    use {super::serialize_wtns, num_bigint::BigInt};

    #[test]
    fn writes_wtns_v2_header_and_fixed_width_values() {
        let bytes = serialize_wtns(&[BigInt::from(1_u8), BigInt::from(2_u8)]);
        assert_eq!(&bytes[..4], b"wtns");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(bytes[60..64].try_into().unwrap()), 2);
        assert_eq!(bytes.len(), 140);
        assert_eq!(bytes[76], 1);
        assert_eq!(bytes[108], 2);
    }
}
