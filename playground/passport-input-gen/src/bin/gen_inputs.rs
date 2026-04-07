use {
    passport_input_gen::{Binary, PassportReader, SOD},
    std::{env, fmt::Write as _, fs, path::Path, process},
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: gen_inputs <dg1_file> <sod_file> [output_dir]");
        eprintln!("Example: gen_inputs ~/Downloads/dg1_full_data.bin ~/Downloads/SOD_full_data.bin ./inputs");
        process::exit(1);
    }

    let dg1_path = &args[1];
    let sod_path = &args[2];
    let output_dir = if args.len() > 3 { &args[3] } else { "." };

    // Read binary files
    let dg1_bytes = fs::read(dg1_path).unwrap_or_else(|e| {
        eprintln!("Failed to read DG1 file '{}': {}", dg1_path, e);
        process::exit(1);
    });
    let sod_bytes = fs::read(sod_path).unwrap_or_else(|e| {
        eprintln!("Failed to read SOD file '{}': {}", sod_path, e);
        process::exit(1);
    });

    println!("DG1: {} bytes from {}", dg1_bytes.len(), dg1_path);
    println!("SOD: {} bytes from {}", sod_bytes.len(), sod_path);

    // Parse SOD
    let mut sod_binary = Binary::from_slice(&sod_bytes);
    let sod = SOD::from_der(&mut sod_binary).unwrap_or_else(|e| {
        eprintln!("Failed to parse SOD: {:?}", e);
        process::exit(1);
    });
    println!("SOD parsed successfully (version {})", sod.version);

    // Create PassportReader (real data, not mock)
    let dg1 = Binary::from_slice(&dg1_bytes);
    let reader = PassportReader::new(dg1, sod.clone(), false, None);

    println!("TBS certificate: {} bytes", sod.certificate.tbs.bytes.len());
    println!("DSC cert signature: {} bytes ({}-bit)", sod.certificate.signature.len(), sod.certificate.signature.len() * 8);

    // Validate passport signature chain
    let csca_index = reader.validate().unwrap_or_else(|e| {
        eprintln!("Passport validation failed: {:?}", e);
        eprintln!("This could mean:");
        eprintln!("  - Wrong DG1 file (try dg1_body.bin vs dg1_full_data.bin)");
        eprintln!("  - SOD uses an unsupported signature algorithm");
        eprintln!("  - CSCA key not in registry");
        process::exit(1);
    });
    println!("Passport validation PASSED (CSCA key index: {})", csca_index);

    // Generate circuit inputs
    let now = chrono::Utc::now().timestamp() as u64;
    let inputs = reader
        .to_circuit_inputs(now, 18, 120, csca_index)
        .unwrap_or_else(|e| {
            eprintln!("Failed to generate circuit inputs: {:?}", e);
            process::exit(1);
        });
    println!("Circuit inputs generated successfully");

    // Extract country from DG1 (offset 5 + 2 = 7 for 3 bytes)
    let country = std::str::from_utf8(&inputs.dg1[7..10]).unwrap_or("UNK");
    println!("Country: {}", country);
    println!("TBS cert length: {}", inputs.passport_validity_contents.dsc_cert_len);
    println!("DSC pubkey offset in cert: {}", inputs.passport_validity_contents.dsc_pubkey_offset_in_dsc_cert);

    // Create output directory
    fs::create_dir_all(output_dir).unwrap_or_else(|e| {
        eprintln!("Failed to create output dir '{}': {}", output_dir, e);
        process::exit(1);
    });

    let pvc = &inputs.passport_validity_contents;

    // Find exponent offset in TBS cert (exponent bytes: big-endian u32)
    let exp_bytes = pvc.dsc_rsa_exponent.to_be_bytes();
    // The exponent in DER is typically encoded as 02 03 01 00 01 for 65537
    // Find the actual exponent value bytes in the TBS cert
    let exp_offset = find_exponent_offset(&pvc.dsc_cert, pvc.dsc_cert_len, &exp_bytes);
    println!("Exponent offset in TBS cert: {}", exp_offset);

    // === t_add_dsc_1300.toml ===
    {
        let mut out = String::new();
        let _ = writeln!(out, "csc_pubkey = {:?}", pvc.csc_pubkey.as_slice());
        let _ = writeln!(out, "csc_key_ne_hash = \"0x0000000000000000000000000000000000000000000000000000000000000000\"");
        let _ = writeln!(out, "# NOTE: csc_key_ne_hash is a Poseidon2 hash computed inside the circuit.");
        let _ = writeln!(out, "# To get the correct value, run the circuit once or compute it externally.");
        let _ = writeln!(out, "csc_pubkey_redc_param = {:?}", pvc.csc_barrett_mu.as_slice());
        let _ = writeln!(out, "salt = \"0x1\"");
        let _ = writeln!(out, "country = \"{}\"", country);
        let _ = writeln!(out, "tbs_certificate = {:?}", pvc.dsc_cert.as_slice());
        let _ = writeln!(out, "dsc_signature = {:?}", pvc.dsc_cert_signature.as_slice());
        let _ = writeln!(out, "exponent = {}", pvc.csc_rsa_exponent);
        let _ = writeln!(out, "tbs_certificate_len = {}", pvc.dsc_cert_len);

        let path = Path::new(output_dir).join("t_add_dsc_1300.toml");
        fs::write(&path, &out).unwrap();
        println!("Wrote {}", path.display());
    }

    // === t_add_id_data_1300.toml ===
    {
        let mut out = String::new();
        let _ = writeln!(out, "comm_in = \"0x0000000000000000000000000000000000000000000000000000000000000000\"");
        let _ = writeln!(out, "# NOTE: comm_in is the output of t_add_dsc_1300. Run that circuit first to get this value.");
        let _ = writeln!(out, "salt_in = \"0x1\"");
        let _ = writeln!(out, "salt_out = \"0x2\"");
        let _ = writeln!(out, "dg1 = {:?}", inputs.dg1.as_slice());
        let _ = writeln!(out, "dsc_pubkey = {:?}", pvc.dsc_pubkey.as_slice());
        let _ = writeln!(out, "dsc_pubkey_redc_param = {:?}", pvc.dsc_barrett_mu.as_slice());
        let _ = writeln!(out, "dsc_pubkey_offset_in_dsc_cert = {}", pvc.dsc_pubkey_offset_in_dsc_cert);
        let _ = writeln!(out, "exponent = {}", pvc.dsc_rsa_exponent);
        let _ = writeln!(out, "exponent_offset_in_dsc_cert = {}", exp_offset);
        let _ = writeln!(out, "sod_signature = {:?}", pvc.dsc_signature.as_slice());
        let _ = writeln!(out, "tbs_certificate = {:?}", pvc.dsc_cert.as_slice());
        let _ = writeln!(out, "signed_attributes = {:?}", pvc.signed_attributes.as_slice());
        let _ = writeln!(out, "e_content = {:?}", pvc.econtent.as_slice());

        let path = Path::new(output_dir).join("t_add_id_data_1300.toml");
        fs::write(&path, &out).unwrap();
        println!("Wrote {}", path.display());
    }

    // === t_add_integrity_commit.toml ===
    {
        let mut out = String::new();
        let _ = writeln!(out, "comm_in = \"0x0000000000000000000000000000000000000000000000000000000000000000\"");
        let _ = writeln!(out, "# NOTE: comm_in is the output of t_add_id_data_1300.");
        let _ = writeln!(out, "salt_in = \"0x2\"");
        let _ = writeln!(out, "dg1 = {:?}", inputs.dg1.as_slice());
        let _ = writeln!(out, "dg1_padded_length = {}", inputs.dg1_padded_length);
        let _ = writeln!(out, "dg1_hash_offset = {}", pvc.dg1_hash_offset);
        let _ = writeln!(out, "signed_attributes = {:?}", pvc.signed_attributes.as_slice());
        let _ = writeln!(out, "signed_attributes_size = {}", pvc.signed_attributes_size);
        let _ = writeln!(out, "e_content = {:?}", pvc.econtent.as_slice());
        let _ = writeln!(out, "e_content_len = {}", pvc.econtent_len);
        let _ = writeln!(out, "private_nullifier = \"0x0000000000000000000000000000000000000000000000000000000000000000\"");
        let _ = writeln!(out, "# NOTE: private_nullifier = Poseidon2(packed_dg1, packed_econtent, packed_sod_sig). Computed inside the circuit.");
        let _ = writeln!(out, "r_dg1 = \"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\"");

        let path = Path::new(output_dir).join("t_add_integrity_commit.toml");
        fs::write(&path, &out).unwrap();
        println!("Wrote {}", path.display());
    }

    // === t_attest.toml ===
    {
        let mut out = String::new();
        let _ = writeln!(out, "root = \"0x0000000000000000000000000000000000000000000000000000000000000000\"");
        let _ = writeln!(out, "# NOTE: root is the Merkle tree root from the sequencer.");
        let _ = writeln!(out, "current_date = \"{}\"", now);
        let _ = writeln!(out, "service_scope = \"0x0000000000000000000000000000000000000000000000000000000000000000\"");
        let _ = writeln!(out, "service_subscope = \"0x0000000000000000000000000000000000000000000000000000000000000000\"");
        let _ = writeln!(out, "dg1 = {:?}", inputs.dg1.as_slice());
        let _ = writeln!(out, "r_dg1 = \"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\"");
        let _ = writeln!(out, "sod_hash = \"0x0000000000000000000000000000000000000000000000000000000000000000\"");
        let _ = writeln!(out, "# NOTE: sod_hash = Poseidon2(packed_econtent). Computed by t_add_integrity_commit.");
        let _ = writeln!(out, "leaf_index = \"0\"");
        let mut merkle_path = String::from("[\n");
        for _ in 0..24 {
            merkle_path.push_str("    \"0x0000000000000000000000000000000000000000000000000000000000000000\",\n");
        }
        merkle_path.push(']');
        let _ = writeln!(out, "merkle_path = {}", merkle_path);
        let _ = writeln!(out, "min_age_required = \"{}\"", inputs.min_age_required);
        let _ = writeln!(out, "max_age_required = \"{}\"", inputs.max_age_required);
        let _ = writeln!(out, "nullifier_secret = \"0x0000000000000000000000000000000000000000000000000000000000000000\"");

        let path = Path::new(output_dir).join("t_attest.toml");
        fs::write(&path, &out).unwrap();
        println!("Wrote {}", path.display());
    }

    // Also write the flat CircuitInputs TOML for reference
    {
        let path = Path::new(output_dir).join("circuit_inputs_raw.toml");
        inputs.save_to_toml_file(&path).unwrap();
        println!("Wrote {} (flat reference)", path.display());
    }

    println!("\nDone! All circuit input files generated in '{}'", output_dir);
    println!("Poseidon2-dependent fields (csc_key_ne_hash, comm_in, private_nullifier, etc.)");
    println!("are set to placeholders. These will be computed by the circuit prover.");
}

/// Find the offset of the RSA exponent value within the TBS certificate.
/// The exponent is typically encoded as ASN.1 INTEGER: 02 03 01 00 01 (for 65537).
fn find_exponent_offset(tbs: &[u8], tbs_len: usize, exp_be: &[u8; 4]) -> usize {
    // Strip leading zero bytes from the big-endian exponent to get the minimal encoding
    let start = exp_be.iter().position(|&b| b != 0).unwrap_or(3);
    let exp_minimal = &exp_be[start..];

    // Search for the exponent bytes in the TBS cert
    for i in 0..tbs_len.saturating_sub(exp_minimal.len()) {
        if &tbs[i..i + exp_minimal.len()] == exp_minimal {
            return i;
        }
    }
    eprintln!("WARNING: Could not find exponent offset in TBS certificate");
    0
}
