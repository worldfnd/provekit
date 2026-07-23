use byteorder::{LittleEndian, ReadBytesExt};
use ruint::aliases::U256;
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{Cursor, Read},
};

fn read_wtns(path: &str) -> eyre::Result<Vec<U256>> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    let mut reader = Cursor::new(bytes);

    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic)?;
    eyre::ensure!(&magic == b"wtns", "invalid WTNS magic");
    eyre::ensure!(reader.read_u32::<LittleEndian>()? == 2, "expected WTNS v2");
    eyre::ensure!(
        reader.read_u32::<LittleEndian>()? == 2,
        "expected exactly two WTNS sections"
    );

    eyre::ensure!(
        reader.read_u32::<LittleEndian>()? == 1,
        "expected WTNS header section"
    );
    let header_size = reader.read_u64::<LittleEndian>()?;
    let field_size = reader.read_u32::<LittleEndian>()? as usize;
    eyre::ensure!(field_size == 32, "expected a 32-byte BN254 field");
    let mut prime = vec![0_u8; field_size];
    reader.read_exact(&mut prime)?;
    let witness_count = reader.read_u32::<LittleEndian>()? as usize;
    eyre::ensure!(
        header_size == (field_size + 8) as u64,
        "unexpected WTNS header size"
    );

    eyre::ensure!(
        reader.read_u32::<LittleEndian>()? == 2,
        "expected WTNS witness section"
    );
    let witness_size = reader.read_u64::<LittleEndian>()? as usize;
    eyre::ensure!(
        witness_size == witness_count * field_size,
        "unexpected WTNS witness byte length"
    );

    let mut witness = Vec::with_capacity(witness_count);
    for _ in 0..witness_count {
        let mut value = [0_u8; 32];
        reader.read_exact(&mut value)?;
        witness.push(U256::from_le_bytes(value));
    }
    eyre::ensure!(
        reader.position() as usize == reader.get_ref().len(),
        "trailing bytes in WTNS file"
    );
    Ok(witness)
}

fn read_inputs(path: &str) -> eyre::Result<HashMap<String, Vec<U256>>> {
    let values: HashMap<String, Vec<String>> = serde_json::from_reader(File::open(path)?)?;
    values
        .into_iter()
        .map(|(name, values)| {
            let values = values
                .into_iter()
                .map(|value| {
                    U256::from_str_radix(&value, 10)
                        .map_err(|error| eyre::eyre!("invalid input {name}: {error}"))
                })
                .collect::<eyre::Result<Vec<_>>>()?;
            Ok((name, values))
        })
        .collect()
}

fn main() -> eyre::Result<()> {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("generate") if args.len() == 2 => {
            circom_witness_rs::generate::build_witness()?;
        }
        Some("check") if args.len() == 5 => {
            let graph = circom_witness_rs::init_graph(&std::fs::read(&args[2])?)?;
            let calculated = circom_witness_rs::calculate_witness(
                read_inputs(&args[3])?,
                &graph,
                None,
            )?;
            let expected = read_wtns(&args[4])?;
            eyre::ensure!(
                calculated == expected,
                "circom-witness-rs witness differs from the reference WTNS"
            );
            println!(
                "circom-witness-rs witness matches all {} reference field elements",
                expected.len()
            );
        }
        _ => {
            eyre::bail!(
                "usage: circom-witness-rs <generate | check GRAPH INPUT WTNS>"
            );
        }
    }
    Ok(())
}
