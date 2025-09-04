use {
    rsa::{
        rand_core::OsRng,
        traits::{PrivateKeyParts, PublicKeyParts},
        BigUint, Pkcs1v15Sign, RsaPrivateKey,
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
    let _mu = compute_redc_param_for_noir(private_key.n());
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

    signature_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_signature_generation() {
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

        let p_bytes = private_key.primes()[0].to_bytes_be();
        let q_bytes = private_key.primes()[1].to_bytes_be();

        let mut p_padded = [0u8; 128];
        let mut q_padded = [0u8; 128];
        p_padded[128 - p_bytes.len()..].copy_from_slice(&p_bytes);
        q_padded[128 - q_bytes.len()..].copy_from_slice(&q_bytes);

        let message = b"test message";

        let signature = generate_rsa_signature_pkcs_from_priv_key(&p_padded, &q_padded, message);

        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 256);
    }
}
