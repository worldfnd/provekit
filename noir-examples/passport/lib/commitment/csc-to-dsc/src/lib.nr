// PROVEKIT MODIFICATION: Removed CSC registry Merkle verification.
// CSC trust is verified off-chain. csc_pubkey is a public input in the circuit.
// Original zkPassport code verified csc_pubkey exists in a certificate registry Merkle tree.
use common::hash_salt_country_tbs;
use utils::types::Alpha3CountryCode;

/*
############################################################
# Circuit A
############################################################
# Verifies the CSC signed the DSC
############################################################

# Inputs/Outputs
############################################################
salt
country
csc_pubkey              (public - verified off-chain)
dsc_pubkey
dsc_data
comm_out                `H(salt, country, tbs_certificate)`

# Checks
############################################################
- Check that dsc_pubkey exists in dsc_tbs at offset dsc_tbs_pubkey_offset
- Check that dsc_sig is the signature of csc_pubkey over dsc_tbs
*/

pub fn commit_to_dsc<let TBS_CERT_SIZE: u32>(
    country: Alpha3CountryCode,
    tbs_certificate: [u8; TBS_CERT_SIZE],
    salt: Field,
) -> Field {
    // Output commitment glue
    let comm_out = hash_salt_country_tbs(salt, country, tbs_certificate);
    comm_out
}
