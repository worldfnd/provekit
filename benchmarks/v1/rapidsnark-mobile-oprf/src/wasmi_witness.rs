//! Interpreter-only Circom 2 witness generation for iOS-safe native runs.

use {
    anyhow::{Context, Result},
    num_bigint::{BigInt, Sign},
    serde_json::Value,
    std::{collections::HashMap, str::FromStr},
    wasmi::{Engine, Linker, Module, Store, TypedFunc},
};

pub(crate) fn generate_wtns(wasm: &[u8], input_json: &str) -> Result<Vec<u8>> {
    let engine = Engine::default();
    let module = Module::new(&engine, wasm).context("compile Circom witness module")?;
    let mut store = Store::new(&engine, ());
    let mut linker = Linker::new(&engine);
    linker.func_wrap(
        "runtime",
        "error",
        |_: i32, _: i32, _: i32, _: i32, _: i32, _: i32| {},
    )?;
    linker.func_wrap("runtime", "exceptionHandler", |_: i32| {})?;
    linker.func_wrap("runtime", "showSharedRWMemory", || {})?;
    linker.func_wrap("runtime", "printErrorMessage", || {})?;
    linker.func_wrap("runtime", "writeBufferMessage", || {})?;
    linker.func_wrap("runtime", "logSetSignal", |_: i32, _: i32| {})?;
    linker.func_wrap("runtime", "logGetSignal", |_: i32, _: i32| {})?;
    linker.func_wrap("runtime", "logFinishComponent", |_: i32| {})?;
    linker.func_wrap("runtime", "logStartComponent", |_: i32| {})?;
    linker.func_wrap("runtime", "log", |_: i32| {})?;
    let instance = linker
        .instantiate(&mut store, &module)
        .context("instantiate Circom witness module")?
        .start(&mut store)
        .context("start Circom witness module")?;

    let get_version = typed::<(), i32>(&instance, &store, "getVersion")?;
    anyhow::ensure!(
        get_version.call(&mut store, ())? == 2,
        "only Circom witness ABI v2 is supported"
    );
    let get_field_num_len32 = typed::<(), i32>(&instance, &store, "getFieldNumLen32")?;
    let get_raw_prime = typed::<(), ()>(&instance, &store, "getRawPrime")?;
    let read_shared = typed::<i32, i32>(&instance, &store, "readSharedRWMemory")?;
    let write_shared = typed::<(i32, i32), ()>(&instance, &store, "writeSharedRWMemory")?;
    let init = typed::<i32, ()>(&instance, &store, "init")?;
    let set_input = typed::<(i32, i32, i32), ()>(&instance, &store, "setInputSignal")?;
    let get_witness_size = typed::<(), i32>(&instance, &store, "getWitnessSize")?;
    let get_witness = typed::<i32, ()>(&instance, &store, "getWitness")?;

    let n32 = usize::try_from(get_field_num_len32.call(&mut store, ())?)
        .context("negative Circom field limb count")?;
    get_raw_prime.call(&mut store, ())?;
    let mut prime_limbs = vec![0_u32; n32];
    for index in 0..n32 {
        prime_limbs[n32 - index - 1] = read_shared.call(&mut store, index as i32)? as u32;
    }
    let prime = from_array32(&prime_limbs);
    init.call(&mut store, 0)?;

    for (name, values) in parse_inputs(input_json)? {
        let (msb, lsb) = fnv(&name);
        for (index, value) in values.into_iter().enumerate() {
            let normalized = ((value % &prime) + &prime) % &prime;
            let limbs = to_array32(&normalized, n32);
            for limb in 0..n32 {
                write_shared.call(
                    &mut store,
                    (limb as i32, limbs[n32 - limb - 1] as i32),
                )?;
            }
            set_input.call(&mut store, (msb as i32, lsb as i32, index as i32))?;
        }
    }

    let witness_size = usize::try_from(get_witness_size.call(&mut store, ())?)
        .context("negative Circom witness size")?;
    let mut witness = Vec::with_capacity(witness_size);
    for index in 0..witness_size {
        get_witness.call(&mut store, index as i32)?;
        let mut limbs = vec![0_u32; n32];
        for limb in 0..n32 {
            limbs[n32 - limb - 1] = read_shared.call(&mut store, limb as i32)? as u32;
        }
        witness.push(from_array32(&limbs));
    }
    Ok(serialize_wtns(&witness))
}

fn typed<Params, Results>(
    instance: &wasmi::Instance,
    store: &Store<()>,
    name: &str,
) -> Result<TypedFunc<Params, Results>>
where
    Params: wasmi::WasmParams,
    Results: wasmi::WasmResults,
{
    instance
        .get_typed_func(store, name)
        .with_context(|| format!("resolve Circom export {name}"))
}

fn parse_inputs(input_json: &str) -> Result<HashMap<String, Vec<BigInt>>> {
    fn flatten(value: &Value, output: &mut Vec<BigInt>) -> Result<()> {
        match value {
            Value::Array(values) => {
                for value in values {
                    flatten(value, output)?;
                }
            }
            Value::String(value) => output.push(BigInt::from_str(value)?),
            Value::Number(value) => output.push(BigInt::from_str(&value.to_string())?),
            _ => anyhow::bail!("unsupported Circom input value: {value}"),
        }
        Ok(())
    }

    serde_json::from_str::<Value>(input_json)?
        .as_object()
        .context("Circom inputs must be an object")?
        .iter()
        .map(|(name, value)| {
            let mut values = Vec::new();
            flatten(value, &mut values)?;
            Ok((name.clone(), values))
        })
        .collect()
}

fn fnv(value: &str) -> (u32, u32) {
    let mut hasher = 0xcbf29ce484222325_u64;
    for byte in value.bytes() {
        hasher ^= u64::from(byte);
        hasher = hasher.wrapping_mul(0x100000001b3);
    }
    ((hasher >> 32) as u32, hasher as u32)
}

fn from_array32(limbs: &[u32]) -> BigInt {
    limbs.iter().fold(BigInt::from(0_u8), |value, limb| {
        (value << 32) + BigInt::from(*limb)
    })
}

fn to_array32(value: &BigInt, size: usize) -> Vec<u32> {
    let (_, bytes) = value.to_bytes_be();
    let mut padded = vec![0_u8; size * 4];
    let start = padded.len() - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    padded
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("four-byte chunk")))
        .collect()
}

fn serialize_wtns(witness: &[BigInt]) -> Vec<u8> {
    const FIELD_BYTES: usize = 32;
    const BN254_SCALAR_MODULUS_LE: [u8; FIELD_BYTES] = [
        1, 0, 0, 240, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129,
        182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
    ];
    let mut output = Vec::with_capacity(76 + witness.len() * FIELD_BYTES);
    output.extend_from_slice(b"wtns");
    output.extend_from_slice(&2_u32.to_le_bytes());
    output.extend_from_slice(&2_u32.to_le_bytes());
    output.extend_from_slice(&1_u32.to_le_bytes());
    output.extend_from_slice(&(4_u64 + FIELD_BYTES as u64 + 4).to_le_bytes());
    output.extend_from_slice(&(FIELD_BYTES as u32).to_le_bytes());
    output.extend_from_slice(&BN254_SCALAR_MODULUS_LE);
    output.extend_from_slice(&(witness.len() as u32).to_le_bytes());
    output.extend_from_slice(&2_u32.to_le_bytes());
    output.extend_from_slice(&((witness.len() * FIELD_BYTES) as u64).to_le_bytes());
    for value in witness {
        let (sign, bytes) = value.to_bytes_le();
        assert!(sign != Sign::Minus, "negative canonical Circom witness");
        output.extend_from_slice(&bytes);
        output.resize(output.len() + FIELD_BYTES - bytes.len(), 0);
    }
    output
}
