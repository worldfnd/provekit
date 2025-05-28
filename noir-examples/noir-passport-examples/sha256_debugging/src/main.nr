/*
############################################################
# Ryan attempt at combining different circuit statements together
############################################################
# Should do three things:
    - Checks that the hash of DG1 exists in SOD
    - Checks that H(SOD) || other stuff is signed by DSC public key
    - Checks that the DSC is signed by the CSC public key
    - Optionally checks that the CSC itself exists within a certificate registry (committed to via Merkle tree)
############################################################

# Inputs/Outputs
    - Takes in DG1 as an untrusted private input
    - Takes in the current date as a public input
    - Takes in the SOD as an untrusted private input
    - Takes in the DSC public key as an untrusted private input
    - Takes in the CSCA public key as a public input 
        (alternatively, we can take it in as an untrusted private input with
         some Merkle proof to a CSCA pubkey tree root somewhere)
    - Optionally, takes in a CSCA Merkle proof as untrusted private input
    - Optionally, takes in a CSCA pubkey tree root as public input
############################################################
*/

fn is_id_card(dg1: [u8; 65]) -> bool {
    // For passport, the last two bytes are 0
    // since the real length is 93 for passports
    // while it is 95 for ID cards
    (dg1[63] != 0) & (dg1[64] != 0)
}

fn debug_sha256(
    // ------------- DSC pubkey verification against H(SOD) + "stuff" -------------
    dg1: [u8; 65],
) {
    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;
    let mut x: u64 = 0;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        println("this is reached");
        x = 3;
        dg1_size = 95;
    }

    // Comparing Noir vs. Ryan SHA-256
    // let other_dg1_hash = sha256::digest(dg1);
    // println("This is Noir's dg1_hash");
    // println(other_dg1_hash);
    // println(
    //     "-----------------------------------------------------------------------------",
    // );

    println("This is the dg1_hash_attempt_1");
    let dg1_hash_attempt_1 = noir_native_sha256::ryan_sha256_noir::sha256_var(dg1, x + 65 - x); // So this gives the correct result but falsely fails R1CS constraints
    println(dg1_hash_attempt_1);
    println(
        "-----------------------------------------------------------------------------",
    );

    // println("This is the dg1_hash_attempt_2");
    // let dg1_hash_attempt_2 = noir_native_sha256::ryan_sha256_noir::sha256_var(dg1, 65 as u64); // This gives the wrong result but succeeds in R1CS constraints
    // println(dg1_hash_attempt_2);
}

// ------ Rotate left / rotate right functionality ------
/// Attempting to mimic the `rotate_left` and `rotate_right` functionality
/// using bit-shifts.
/// WARNING: CANNOT USE THIS IF ROTATION_AMT == 0
fn rotate_left_via_shift_u32(val: u32, rotation_amt: u8) -> u32 {
    let rotation_amt = rotation_amt % 32;
    print("val: ");
    println(val);
    print("rotation_amt: ");
    println(rotation_amt);
    // 01234567|
    // 012|34567 -> 34567|012
    // We can do this with bit-masking and/or shifting
    let left_side_already_moved = val >> (32 - rotation_amt);
    print("left_side_already_moved: ");
    println(left_side_already_moved);
    let right_side_already_moved = val << rotation_amt;
    print("right_side_already_moved: ");
    println(right_side_already_moved);
    left_side_already_moved | right_side_already_moved
}

/// WARNING: CANNOT USE THIS IF ROTATION_AMT == 0
/// Also small note -- this is the elegant but probably inefficient way of doing it
fn rotate_right_via_shift_u32(val: u32, rotation_amt: u8) -> u32 {
    let rotation_amt = rotation_amt % 32;
    rotate_left_via_shift_u32(val, 32 - rotation_amt)
}

fn test_rotation_stuff(val: u32, rotation_amt: u8) {
    let const_val = 3584795861;
    let const_rotation_amt = 6;

    let var_var_result = rotate_right_via_shift_u32(val, rotation_amt);
    print("var_var_result: ");
    println(var_var_result);
    let var_const_result = rotate_right_via_shift_u32(val, const_rotation_amt);
    print("var_const_result: ");
    println(var_const_result);
    let const_var_result = rotate_right_via_shift_u32(const_val, rotation_amt);
    print("const_var_result: ");
    println(const_var_result);
    let const_const_result = rotate_right_via_shift_u32(const_val, const_rotation_amt);
    print("const_const_result: ");
    println(const_const_result);
}

fn main(dg1: [u8; 65]) {
    debug_sha256(dg1);
}
