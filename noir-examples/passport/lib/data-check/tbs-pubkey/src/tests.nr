use super::{verify_ecdsa_pubkey_in_tbs, verify_rsa_pubkey_in_tbs};

#[test]
fn test_verify_rsa_pubkey_in_tbs() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut rsa_pubkey: [u8; 256] = [0; 256];
    for i in 0..rsa_pubkey.len() {
        rsa_pubkey[i] = i as u8;
    }
    for i in 0..rsa_pubkey.len() {
        tbs[i + 100] = rsa_pubkey[i];
    }
    verify_rsa_pubkey_in_tbs(rsa_pubkey, tbs);
}

#[test(should_fail_with = "Index out of bounds")]
fn test_verify_rsa_pubkey_in_tbs_fail() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut rsa_pubkey: [u8; 256] = [0; 256];
    for i in 0..rsa_pubkey.len() {
        rsa_pubkey[i] = i as u8;
    }
    for i in 0..rsa_pubkey.len() {
        tbs[i + 100] = rsa_pubkey[i];
    }
    // Corrupt a few bytes of the public key
    tbs[105] = 0;
    tbs[106] = 0;
    tbs[107] = 0;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, tbs);
}

#[test]
fn test_verify_ecdsa_pubkey_in_tbs() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut ecdsa_pubkey_x: [u8; 32] = [0; 32];
    let mut ecdsa_pubkey_y: [u8; 32] = [0; 32];
    for i in 0..ecdsa_pubkey_x.len() {
        ecdsa_pubkey_x[i] = i as u8 + 2;
    }
    for i in 0..ecdsa_pubkey_y.len() {
        ecdsa_pubkey_y[i] = i as u8 + 1;
    }
    for i in 0..ecdsa_pubkey_x.len() {
        tbs[i + 100] = ecdsa_pubkey_x[i];
        tbs[i + 100 + 32] = ecdsa_pubkey_y[i];
    }
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}

#[test(should_fail_with = "Index out of bounds")]
fn test_verify_ecdsa_pubkey_in_tbs_fail() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut ecdsa_pubkey_x: [u8; 32] = [0; 32];
    let mut ecdsa_pubkey_y: [u8; 32] = [0; 32];
    for i in 0..ecdsa_pubkey_x.len() {
        ecdsa_pubkey_x[i] = i as u8 + 2;
    }
    for i in 0..ecdsa_pubkey_y.len() {
        ecdsa_pubkey_y[i] = i as u8 + 1;
    }
    for i in 0..ecdsa_pubkey_x.len() {
        tbs[i + 100] = ecdsa_pubkey_x[i];
        tbs[i + 100 + 32] = ecdsa_pubkey_y[i];
    }
    // Corrupt a few bytes of the public key x coordinate
    tbs[105] = 0;
    tbs[106] = 0;
    tbs[107] = 0;
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}

#[test(should_fail_with = "Public key y coord not found in TBS")]
fn test_verify_ecdsa_pubkey_in_tbs_fail_y_coord() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut ecdsa_pubkey_x: [u8; 32] = [0; 32];
    let mut ecdsa_pubkey_y: [u8; 32] = [0; 32];
    for i in 0..ecdsa_pubkey_x.len() {
        ecdsa_pubkey_x[i] = i as u8 + 2;
    }
    for i in 0..ecdsa_pubkey_y.len() {
        ecdsa_pubkey_y[i] = i as u8 + 1;
    }
    for i in 0..ecdsa_pubkey_x.len() {
        tbs[i + 100] = ecdsa_pubkey_x[i];
        tbs[i + 100 + 32] = ecdsa_pubkey_y[i];
    }
    // Corrupt a few bytes of the public key y coordinate
    tbs[100 + 5 + 32] = 0;
    tbs[100 + 6 + 32] = 0;
    tbs[100 + 7 + 32] = 0;
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}
