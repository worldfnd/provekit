use partial_sha256::{
    SHA256State, sha256_start, commit_to_sha256_state_and_data, commit_to_data_chunk,
};

global CHUNK1_SIZE: u32 = 640;

fn main(
    salt: Field,
    chunk1: [u8; CHUNK1_SIZE],
) -> pub Field {
    let state1: SHA256State = sha256_start(chunk1);
    let data_comm1 = commit_to_data_chunk(salt, chunk1);
    let comm_out = commit_to_sha256_state_and_data(salt, state1, CHUNK1_SIZE, data_comm1);
    comm_out
}
