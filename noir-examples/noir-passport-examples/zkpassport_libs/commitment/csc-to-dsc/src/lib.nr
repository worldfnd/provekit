use common::{
    calculate_certificate_registry_leaf, compute_merkle_root, CSC_CERT_TYPE, hash_salt_country_tbs,
};

/*
############################################################
# Circuit A
############################################################
# Verifies the CSC signed the DSC
############################################################

# Inputs/Outputs
############################################################
certificate_registry_root (public)
certificate_registry
salt
country
csc_pubkey
dsc_pubkey
dsc_data
comm_out                `H(salt, country, dsc_pubkey)`

# Checks
############################################################
- Check that leaf `H(registry_id, cert_type, country, csc_pubkey)` exists in tree with root certificate_registry_root
- Check that dsc_pubkey exists in dsc_tbs at offset dsc_tbs_pubkey_offset
- Check that dsc_sig is the signature of csc_pubkey over dsc_tbs
*/

pub fn commit_to_dsc<let CSC_KEY_SIZE: u32, let HASH_PATH_SIZE: u32, let TBS_CERT_SIZE: u32>(
    certificate_registry_root: Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; HASH_PATH_SIZE],
    certificate_tags: [Field; 3],
    country: str<3>,
    tbs_certificate: [u8; TBS_CERT_SIZE],
    salt: Field,
    csc_pubkey: [u8; CSC_KEY_SIZE],
) -> Field {
    // Verify csc_pubkey exists in certificate registry
    let leaf: Field =
        calculate_certificate_registry_leaf(certificate_tags, CSC_CERT_TYPE, country, csc_pubkey);
    let root = compute_merkle_root(
        leaf,
        certificate_registry_index,
        certificate_registry_hash_path,
    );
    assert(root == certificate_registry_root, "Certificate registry root mismatch");
    // Output commitment glue
    let comm_out = hash_salt_country_tbs(salt, country, tbs_certificate);
    comm_out
}
