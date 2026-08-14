//! Short-lived native witness generator for the 32-bit E15 WebAuthn lane.
//!
//! The generated Rust witness engine is intentionally kept out of the main
//! Rapidsnark adapter. The adapter loads this library, copies the WTNS into a
//! caller-owned buffer, and unloads it before the 1.73 GiB proving key is
//! mapped. This is required to fit the complete input-to-proof path in the
//! E15's 32-bit address space.

use {
    num_bigint::{BigInt, Sign},
    serde_json::Value,
};

mod witness {
    rust_witness::witness!(webauthndefault);
}

const INPUTS: &str =
    include_str!("../../circom/web/dist/assets/webauthn/webauthn_default.input.json");

fn parse_inputs(input_json: &str) -> std::collections::HashMap<String, Vec<BigInt>> {
    fn flatten(value: &Value, output: &mut Vec<BigInt>) {
        match value {
            Value::Array(values) => values.iter().for_each(|value| flatten(value, output)),
            Value::String(value) => {
                output.push(value.parse::<BigInt>().expect("Circom decimal input"))
            }
            Value::Number(value) => {
                output.push(value.to_string().parse::<BigInt>().expect("Circom numeric input"))
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

fn serialize_wtns(witness: &[BigInt]) -> Vec<u8> {
    const FIELD_BYTES: usize = 32;
    const BN254_SCALAR_MODULUS_LE: [u8; FIELD_BYTES] = [
        1, 0, 0, 240, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129,
        129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
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

/// Generate the live WTNS into a caller-owned buffer.
///
/// Returns the serialized length, or zero when `out` is null or the provided
/// buffer is too small. The caller owns the buffer and may unload this helper
/// immediately after the function returns.
#[no_mangle]
pub unsafe extern "C" fn mobench_generate_webauthn_witness(
    out: *mut u8,
    out_len: usize,
) -> usize {
    if out.is_null() {
        return 0;
    }
    let values = witness::webauthndefault_witness(parse_inputs(INPUTS));
    let bytes = serialize_wtns(&values);
    if bytes.len() > out_len {
        return 0;
    }
    // SAFETY: The caller promises that `out` points to a writable buffer of
    // at least `out_len` bytes; the explicit length check bounds the copy.
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    bytes.len()
}
