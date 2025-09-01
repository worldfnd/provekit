pub mod generate_dummy_prover_toml;
pub mod rsa_stuff;
pub mod usa_passport_generator;
pub mod zkpassport_constants;

use crate::{
    generate_dummy_prover_toml::{
        dg1_bytes_with_birthdate_expiry_date,
        generate_prover_toml_string_from_custom_dg1_date_and_required_age,
    },
    usa_passport_generator::{generate_age_testcases, generate_usa_passport_sample},
};

fn main() {
    println!("Generating age verification testcases...");

    // Generate age testcases: below 18, exactly 18, above 18 (max age 70)
    let testcases = generate_age_testcases();
    for (name, toml_content) in testcases {
        let filename = format!("{}_Prover.toml", name);
        let complete_age_check_path = format!("../complete_age_check/{}", filename);
        std::fs::write(&complete_age_check_path, toml_content)
            .expect(&format!("Unable to write {}", complete_age_check_path));
        println!("Generated: {}", complete_age_check_path);
    }

    println!("\nTestcases created:");
    println!("- below_18_Prover.toml  (17 years old)");
    println!("- exactly_18_Prover.toml (18 years old)");
    println!("- above_18_Prover.toml   (19 years old");
}
