//! SHA256-based Proof-of-Work implementation.

use {
    sha2::{Digest, Sha256},
    spongefish_pow::PowStrategy,
};

/// SHA256-based proof-of-work strategy.
#[derive(Clone, Copy, Debug)]
pub struct Sha256PoW {
    challenge: [u8; 32],
    bits: f64,
}

impl PowStrategy for Sha256PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!(
            (0.0..256.0).contains(&bits),
            "bits must be between 0 and 256 for SHA256"
        );
        Self { challenge, bits }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let hash = self.compute_hash(nonce);
        self.has_required_leading_zeros(&hash)
    }

    fn solve(&mut self) -> Option<u64> {
        // Brute force search for nonce
        for nonce in 0..u64::MAX {
            if self.check(nonce) {
                return Some(nonce);
            }
        }
        None
    }
}

impl Sha256PoW {
    fn compute_hash(&self, nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.challenge);
        hasher.update(&nonce.to_le_bytes());
        hasher.finalize().into()
    }

    fn has_required_leading_zeros(&self, hash: &[u8; 32]) -> bool {
        let required_bits = self.bits as usize;
        let full_bytes = required_bits / 8;
        let remaining_bits = required_bits % 8;

        // Check full zero bytes
        for byte in hash.iter().take(full_bytes) {
            if *byte != 0 {
                return false;
            }
        }

        // Check remaining bits in the next byte
        if remaining_bits > 0 && full_bytes < hash.len() {
            let mask = 0xFF << (8 - remaining_bits);
            if hash[full_bytes] & mask != 0 {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_sha256() {
        let challenge = [1u8; 32];
        let mut pow = Sha256PoW::new(challenge, 4.0);

        // Find a nonce
        let nonce = pow.solve().expect("Should find nonce");

        // Verify it
        assert!(pow.check(nonce));
    }

    #[test]
    fn test_leading_zeros() {
        let pow = Sha256PoW {
            challenge: [0; 32],
            bits: 8.0,
        };

        assert!(pow.has_required_leading_zeros(&[0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!pow.has_required_leading_zeros(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }
}
