use crate::parser::{binary::Binary, sod::SOD};

mod binary;
mod dsc;
mod oid_registry;
mod sod;
mod types;
mod utils;

pub struct PassportReader {
    pub dg1: Binary,
    pub sod: SOD,
}

impl PassportReader {
    pub fn print_passport(&self) {
        let is_id_card = self.dg1.len() == 95;
        let mrz_data = self.dg1.slice(5, self.dg1.len()).to_number_array();
        let mrz = String::from_utf8_lossy(&mrz_data).to_string();

        println!("MRZ: {}", mrz);

        let extract = |start: usize, end: usize| {
            String::from_utf8_lossy(&mrz_data[start..end])
                .trim()
                .to_string()
        };

        let name = extract(
            if is_id_card { 60 } else { 5 },
            if is_id_card { 90 } else { 44 },
        );
        let date_of_birth = extract(
            if is_id_card { 30 } else { 57 },
            if is_id_card { 36 } else { 63 },
        );
        let nationality = extract(
            if is_id_card { 45 } else { 54 },
            if is_id_card { 48 } else { 57 },
        );
        let gender = extract(
            if is_id_card { 37 } else { 64 },
            if is_id_card { 38 } else { 65 },
        );
        let passport_number = extract(
            if is_id_card { 5 } else { 44 },
            if is_id_card { 14 } else { 53 },
        );
        let passport_expiry = extract(
            if is_id_card { 38 } else { 65 },
            if is_id_card { 44 } else { 71 },
        );

        println!("Name: {}", name);
        println!("Date of Birth: {}", date_of_birth);
        println!("Nationality: {}", nationality);
        println!("Gender: {}", gender);
        println!("Passport Number: {}", passport_number);
        println!("Passport Expiry: {}", passport_expiry);

        for (group_number, hash_value) in self
            .sod
            .encap_content_info
            .e_content
            .data_group_hash_values
            .values
            .iter()
        {
            println!(
                "Data Group {} hash: {}",
                group_number,
                hex::encode(hash_value.to_number_array())
            );
            if *group_number == 1 {
                println!("Data Group 1 value: {:?}", self.dg1.to_number_array());
            }
        }

        println!(
            "Data Groups Hash Algorithm: {:?}",
            self.sod.encap_content_info.e_content.hash_algorithm
        );
    }
}
//   }
