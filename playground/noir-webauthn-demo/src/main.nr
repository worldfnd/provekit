global CLIENT_DATA_JSON_MAX_LEN: u32 = 256;
global AUTHENTICATOR_DATA_MAX_LEN: u32 = 64;
global P256_LIMBS: u32 = 3;
global P256_SCALAR_SLICES: u32 = 65;

fn main(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    client_data_json: BoundedVec<u8, CLIENT_DATA_JSON_MAX_LEN>,
    authenticator_data: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN>,
    challenge: [u8; 32],
    challenge_index: u32,
    r_point_y: [u8; 32],
    message_limbs: [u128; P256_LIMBS],
    public_key_x_limbs: [u128; P256_LIMBS],
    public_key_y_limbs: [u128; P256_LIMBS],
    signature_r_limbs: [u128; P256_LIMBS],
    signature_s_limbs: [u128; P256_LIMBS],
    r_point_y_limbs: [u128; P256_LIMBS],
    s_g_limbs: [u128; P256_LIMBS],
    s_g_slices: [u8; P256_SCALAR_SLICES],
    s_g_skew: bool,
    s_g_borrow_low: bool,
    s_g_borrow_mid: bool,
    s_p_limbs: [u128; P256_LIMBS],
    s_p_slices: [u8; P256_SCALAR_SLICES],
    s_p_skew: bool,
    s_p_borrow_low: bool,
    s_p_borrow_mid: bool,
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
        message_limbs,
        public_key_x_limbs,
        public_key_y_limbs,
        signature_r_limbs,
        signature_s_limbs,
        r_point_y_limbs,
        s_g_limbs,
        s_g_slices,
        s_g_skew,
        s_g_borrow_low,
        s_g_borrow_mid,
        s_p_limbs,
        s_p_slices,
        s_p_skew,
        s_p_borrow_low,
        s_p_borrow_mid,
    );
    assert(valid, "webauthn signature verification failed");
}
