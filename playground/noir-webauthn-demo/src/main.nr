global CLIENT_DATA_JSON_MAX_LEN: u32 = 256;
global AUTHENTICATOR_DATA_MAX_LEN: u32 = 64;

fn main(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    client_data_json: BoundedVec<u8, CLIENT_DATA_JSON_MAX_LEN>,
    authenticator_data: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN>,
    challenge: [u8; 32],
    challenge_index: u32,
    r_point_y: [u8; 32],
) {
    let valid = webauthn::verify_signature(
        public_key_x,
        public_key_y,
        signature,
        client_data_json,
        authenticator_data,
        challenge,
        challenge_index,
        r_point_y,
    );
    assert(valid, "webauthn signature verification failed");
}
