use commitment::hash_salt_country_tbs;
use partial_sha256::{
    SHA256State, sha256_continue, sha256_finalize, verify_sha256_state_and_data_commitment, commit_to_data_chunk,
};
use sig_check_rsa::verify_rsa_signature;
use utils::types::{Alpha3CountryCode, SHA256Digest};

global CHUNK1_SIZE: u32 = 640;
global CHUNK2_SIZE: u32 = 640;
global TBS_CERT_SIZE: u32 = 1300;

fn main(
    comm_in: pub Field,
    csc_pubkey: pub [u8; 512],
    salt: Field,
    country: Alpha3CountryCode,
    state1: SHA256State,
    tbs_certificate: [u8; TBS_CERT_SIZE],
    tbs_certificate_len: u32,
    csc_pubkey_redc_param: [u8; 513],
    dsc_signature: [u8; 512],
    exponent: u32,
    salt_out: Field,
) -> pub Field {
    let mut chunk1: [u8; CHUNK1_SIZE] = [0; CHUNK1_SIZE];
    for i in 0..CHUNK1_SIZE {
        chunk1[i] = tbs_certificate[i];
    }

    let data_comm1 = commit_to_data_chunk(salt, chunk1);
    verify_sha256_state_and_data_commitment(comm_in, salt, state1, CHUNK1_SIZE, data_comm1);

    let remaining_size: u32 = if tbs_certificate_len > CHUNK1_SIZE {
        tbs_certificate_len - CHUNK1_SIZE
    } else {
        0
    };

    let num_full_blocks = remaining_size / 64;
    let full_block_bytes = num_full_blocks * 64;
    let final_partial_bytes = remaining_size - full_block_bytes;

    let mut chunk2: [u8; CHUNK2_SIZE] = [0; CHUNK2_SIZE];
    for i in 0..CHUNK2_SIZE {
        chunk2[i] = tbs_certificate[CHUNK1_SIZE + i];
    }

    let state2 = sha256_continue(state1, chunk2, full_block_bytes);

    let mut final_block: [u8; 64] = [0; 64];
    for i in 0..64 {
        if i < final_partial_bytes {
            final_block[i] = tbs_certificate[CHUNK1_SIZE + full_block_bytes + i];
        }
    }

    let tbs_hash: SHA256Digest = sha256_finalize(state2, final_block, final_partial_bytes, tbs_certificate_len);

    assert(
        verify_rsa_signature::<512, 0, 1300, 32>(
            csc_pubkey,
            dsc_signature,
            csc_pubkey_redc_param,
            exponent,
            tbs_hash,
        ),
        "RSA signature verification failed",
    );

    let comm_out = hash_salt_country_tbs(
        salt_out,
        country,
        tbs_certificate,
    );

    comm_out
}
