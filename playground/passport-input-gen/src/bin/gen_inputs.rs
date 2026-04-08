use std::{env, fs, process};

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

    let dg1_bytes = fs::read(dg1_path).unwrap_or_else(|e| {
        eprintln!("Failed to read DG1 file '{}': {}", dg1_path, e);
        process::exit(1);
    });
    let sod_bytes = fs::read(sod_path).unwrap_or_else(|e| {
        eprintln!("Failed to read SOD file '{}': {}", sod_path, e);
        process::exit(1);
    });

    println!("DG1: {} bytes, SOD: {} bytes", dg1_bytes.len(), sod_bytes.len());

    let now = chrono::Utc::now().timestamp() as u64;
    let (inputs, csca_index) =
        passport_input_gen::generate_all_inputs(&dg1_bytes, &sod_bytes, now, 18, 0)
            .unwrap_or_else(|e| {
                eprintln!("Failed to generate inputs: {}", e);
                process::exit(1);
            });

    println!("Passport validated (CSCA key index: {})", csca_index);
    println!("Country: {}", inputs.country());
    println!("TBS cert: {} bytes", inputs.passport_validity_contents.dsc_cert_len);

    inputs.save_stage_inputs(output_dir).unwrap_or_else(|e| {
        eprintln!("Failed to write stage inputs: {}", e);
        process::exit(1);
    });

    // Also write flat reference TOML
    inputs
        .save_to_toml_file(std::path::Path::new(output_dir).join("circuit_inputs_raw.toml"))
        .unwrap();

    println!("Done! All circuit input files generated in '{}'", output_dir);
}
