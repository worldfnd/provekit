//! Circom/Arkworks proof-only benchmark for 32-bit Android.
//!
//! Each APK carries one independently validated SnarkJS WTNS and matching zkey
//! as native-library resources. Loading and correctness canaries happen outside
//! the measured proving interval.

use {
    circom_prover::prover::{self, CircomProof, ProofLib},
    num_bigint::BigUint,
    std::{
        env, fs,
        hint::black_box,
        path::{Path, PathBuf},
        sync::OnceLock,
        thread,
        time::Instant,
    },
};

const ZKEY_RESOURCE: &str = "libmobench_proving_key.so";
const WTNS_RESOURCE: &str = "libmobench_witness.so";

pub(crate) struct PreparedProve {
    witnesses: Vec<BigUint>,
    zkey_path: String,
}

fn checked_file(path: PathBuf) -> PathBuf {
    let metadata = fs::metadata(&path)
        .unwrap_or_else(|error| panic!("read fixture metadata for {}: {error}", path.display()));
    assert!(
        metadata.is_file(),
        "fixture is not a file: {}",
        path.display()
    );
    path
}

fn resource_path(name: &str) -> PathBuf {
    if let Some(directory) = env::var_os("MOBENCH_CIRCOM_RESOURCE_DIR") {
        return checked_file(PathBuf::from(directory).join(name));
    }

    #[cfg(target_os = "android")]
    {
        let library_name = format!("lib{}.so", env!("CARGO_PKG_NAME").replace('-', "_"));
        let maps = fs::read_to_string("/proc/self/maps").expect("read Android process maps");
        let library_path = maps
            .lines()
            .filter_map(|line| line.split_whitespace().last())
            .map(|path| path.trim_end_matches(" (deleted)"))
            .find(|path| path.ends_with(&library_name))
            .unwrap_or_else(|| panic!("locate {library_name} in Android process maps"));
        return checked_file(
            PathBuf::from(library_path)
                .parent()
                .expect("Android benchmark library has a parent")
                .join(name),
        );
    }

    #[cfg(not(target_os = "android"))]
    {
        let executable = env::current_exe().expect("resolve benchmark executable path");
        checked_file(
            executable
                .parent()
                .expect("benchmark executable has a parent")
                .join(name),
        )
    }
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    let end = offset.checked_add(4).expect("WTNS u32 offset overflow");
    let value = u32::from_le_bytes(
        bytes
            .get(*offset..end)
            .expect("truncated WTNS u32")
            .try_into()
            .expect("WTNS u32 width"),
    );
    *offset = end;
    value
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> u64 {
    let end = offset.checked_add(8).expect("WTNS u64 offset overflow");
    let value = u64::from_le_bytes(
        bytes
            .get(*offset..end)
            .expect("truncated WTNS u64")
            .try_into()
            .expect("WTNS u64 width"),
    );
    *offset = end;
    value
}

fn parse_wtns(path: &Path) -> Vec<BigUint> {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("read WTNS {}: {error}", path.display()));
    assert_eq!(
        bytes.get(..4),
        Some(b"wtns".as_slice()),
        "invalid WTNS magic"
    );
    let mut offset = 4;
    assert_eq!(read_u32(&bytes, &mut offset), 2, "unsupported WTNS version");
    let section_count = read_u32(&bytes, &mut offset);
    let mut field_bytes = None;
    let mut witness_count = None;
    let mut witness_section = None;

    for _ in 0..section_count {
        let section_id = read_u32(&bytes, &mut offset);
        let section_len = usize::try_from(read_u64(&bytes, &mut offset))
            .expect("WTNS section length exceeds usize");
        let end = offset
            .checked_add(section_len)
            .expect("WTNS section offset overflow");
        let section = bytes.get(offset..end).expect("truncated WTNS section");
        match section_id {
            1 => {
                let mut header_offset = 0;
                let width = usize::try_from(read_u32(section, &mut header_offset))
                    .expect("WTNS field width exceeds usize");
                let prime_end = header_offset
                    .checked_add(width)
                    .expect("WTNS prime offset overflow");
                section
                    .get(header_offset..prime_end)
                    .expect("truncated WTNS prime");
                header_offset = prime_end;
                field_bytes = Some(width);
                witness_count = Some(
                    usize::try_from(read_u32(section, &mut header_offset))
                        .expect("WTNS witness count exceeds usize"),
                );
            }
            2 => witness_section = Some(section),
            _ => {}
        }
        offset = end;
    }

    let width = field_bytes.expect("WTNS header section missing");
    let count = witness_count.expect("WTNS witness count missing");
    let witness_bytes = witness_section.expect("WTNS witness section missing");
    assert_eq!(
        witness_bytes.len(),
        width
            .checked_mul(count)
            .expect("WTNS witness size overflow"),
        "WTNS witness section length mismatch"
    );
    witness_bytes
        .chunks_exact(width)
        .map(BigUint::from_bytes_le)
        .collect()
}

fn prove(prepared: PreparedProve) -> CircomProof {
    prover::prove(
        ProofLib::Arkworks,
        prepared.zkey_path,
        thread::spawn(move || prepared.witnesses),
    )
    .expect("Mopro Arkworks proof")
}

fn validation_gate() {
    static VALIDATED: OnceLock<()> = OnceLock::new();
    VALIDATED.get_or_init(|| {
        let zkey = resource_path(ZKEY_RESOURCE);
        let witness = resource_path(WTNS_RESOURCE);
        let proof = prove(PreparedProve {
            witnesses: parse_wtns(&witness),
            zkey_path: zkey.to_string_lossy().into_owned(),
        });
        assert!(
            prover::verify(
                ProofLib::Arkworks,
                zkey.to_string_lossy().into_owned(),
                proof.clone(),
            )
            .expect("verify valid Mopro Arkworks canary"),
            "valid Mopro Arkworks canary was rejected"
        );

        let mut tampered = proof;
        if let Some(public_input) = tampered.pub_inputs.0.first_mut() {
            *public_input += BigUint::from(1u32);
        } else {
            // Use the valid point at infinity instead of corrupting a curve
            // coordinate. Arkworks rejects malformed affine points while
            // deserializing them, before Groth16 verification can return false.
            tampered.proof.a.x = BigUint::from(0u32);
            tampered.proof.a.y = BigUint::from(0u32);
            tampered.proof.a.z = BigUint::from(0u32);
        }
        let rejected = match prover::verify(
            ProofLib::Arkworks,
            zkey.to_string_lossy().into_owned(),
            tampered,
        ) {
            Ok(valid) => !valid,
            Err(_) => true,
        };
        assert!(rejected, "tampered Mopro Arkworks canary was accepted");
    });
}

pub(crate) fn setup_prove() -> PreparedProve {
    validation_gate();
    let zkey = resource_path(ZKEY_RESOURCE);
    let witness = resource_path(WTNS_RESOURCE);
    let zkey_size = fs::metadata(&zkey).expect("read zkey metadata").len();
    let witness_size = fs::metadata(&witness).expect("read WTNS metadata").len();
    mobench_sdk::record_run_u64("zkey_size_bytes", zkey_size);
    mobench_sdk::record_run_u64("witness_size_bytes", witness_size);
    mobench_sdk::record_run_u64("proving_payload_size_bytes", zkey_size + witness_size);
    PreparedProve {
        witnesses: parse_wtns(&witness),
        zkey_path: zkey.to_string_lossy().into_owned(),
    }
}

pub(crate) fn bench_prove(prepared: PreparedProve) {
    let started = Instant::now();
    let proof = prove(prepared);
    let prove_time_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let proof_size = serde_json::to_vec(&proof)
        .expect("serialize exact Arkworks Groth16 proof")
        .len() as u64;
    mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", proof_size);
    black_box(proof);
}
