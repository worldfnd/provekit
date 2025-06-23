use {
    rsa::{
        pkcs1v15::{Signature, VerifyingKey},
        rand_core::OsRng,
        signature::Verifier,
        traits::{PrivateKeyParts, PublicKeyParts},
        BigUint, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
    },
    sha2::{Digest, Sha256},
};

// From Noir:
// `redc_param` = 2^{modulus_bits() * 2 + BARRETT_REDUCTION_OVERFLOW_BITS} /
// modulus
fn compute_redc_param_for_noir(n: &BigUint) -> BigUint {
    const BARRETT_REDUCTION_OVERFLOW_BITS: usize = 4;
    let k = n.bits();
    let b = BigUint::from(1u8) << (2 * k + BARRETT_REDUCTION_OVERFLOW_BITS);
    &b / n
}

/// Generates and prints a random set of RSA params, as bytes.
pub fn generate_random_rsa_params() {
    let mut rng = OsRng; // rand@0.8
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    dbg!(&private_key.e().to_bytes_be()); // public exponent
    dbg!(&private_key.n().to_bytes_be());
    let mu = compute_redc_param_for_noir(private_key.n());
    dbg!(&mu.to_bytes_be()); // Barrett reduction REDC param (for Noir specifically)
    dbg!("Primes start here");
    private_key.primes().iter().for_each(|prime| {
        dbg!(prime.to_bytes_be());
    });
    dbg!("Primes end here");
}

/// Returns the signature bytes.
pub fn generate_rsa_signature_pkcs_from_priv_key(
    rsa_priv_key_p_bytes: &[u8; 128],
    rsa_priv_key_q_bytes: &[u8; 128],
    message_bytes: &[u8],
) -> Vec<u8> {
    let prime_p = BigUint::from_bytes_be(&rsa_priv_key_p_bytes[..]);
    let prime_q = BigUint::from_bytes_be(&rsa_priv_key_q_bytes[..]);
    let e = BigUint::from(65537_u64);
    let private_key =
        RsaPrivateKey::from_p_q(prime_p, prime_q, e).expect("failed to read key from prime bytes");
    let public_key = private_key.to_public_key();
    let padding = Pkcs1v15Sign::new::<Sha256>(); // We explicitly want PKCSv1.15, not PSS

    let digest_in = Sha256::digest(message_bytes);
    let signature_bytes = private_key
        .sign(padding.clone(), &digest_in)
        .expect("We should be able to sign");

    public_key
        .verify(padding, &digest_in, &signature_bytes)
        .expect("Error: verification failed");
    dbg!("Everything worked!");

    signature_bytes
}

pub fn test_rsa_verification(
    rsa_pubkey_bytes: &[u8; 256],
    signature_bytes: &[u8; 256],
    message_bytes: &[u8],
) {
    let e = BigUint::from(65537_u32);
    let n = BigUint::from_bytes_be(rsa_pubkey_bytes);

    // Recall: RSA signature basically means that we will compute
    // s := (H(m))^e \mod n
    // And then we will check whether s^d \mod n \equiv 1 \mod n

    let rsa_pubkey = RsaPublicKey::new(n, e).unwrap();
    let verification_key = VerifyingKey::<Sha256>::new(rsa_pubkey);
    let signature = Signature::try_from(&signature_bytes[..]).unwrap();
    verification_key
        .verify(message_bytes, &signature)
        .expect("failed to verify");
    dbg!("Verified!");
}
