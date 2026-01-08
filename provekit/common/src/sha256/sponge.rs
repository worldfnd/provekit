// SHA256 sponge for Fiat-Shamir transcripts
//
// This module provides a SHA256-based duplex sponge construction
// that can be used for Fiat-Shamir transformations in WHIR proofs.

use {sha2::Digest, spongefish::duplex_sponge::DuplexSpongeInterface, zeroize::Zeroize};

/// SHA256 duplex sponge for Fiat-Shamir transcripts.
///
/// Uses SHA256 as the underlying hash function with a simple sponge construction.
#[derive(Clone)]
pub struct Sha256Sponge {
    /// Current state buffer
    state: Vec<u8>,
    /// Mode: true = absorbing, false = squeezing
    absorbing: bool,
    /// Output buffer for squeezing
    output_buffer: Vec<u8>,
    /// Position in output buffer
    output_pos: usize,
}

impl Default for Sha256Sponge {
    fn default() -> Self {
        Self {
            state: Vec::new(),
            absorbing: true,
            output_buffer: Vec::new(),
            output_pos: 0,
        }
    }
}

impl DuplexSpongeInterface<u8> for Sha256Sponge {
    fn new(iv: [u8; 32]) -> Self {
        Self {
            state: iv.to_vec(),
            absorbing: true,
            output_buffer: Vec::new(),
            output_pos: 0,
        }
    }

    fn absorb_unchecked(&mut self, input: &[u8]) -> &mut Self {
        // If we were squeezing, finalize that phase
        if !self.absorbing {
            // Ratchet: hash the current state
            let hash = sha2::Sha256::digest(&self.state);
            self.state = hash.to_vec();
            self.output_buffer.clear();
            self.output_pos = 0;
            self.absorbing = true;
        }

        // Absorb new input
        self.state.extend_from_slice(input);
        self
    }

    fn squeeze_unchecked(&mut self, output: &mut [u8]) -> &mut Self {
        // If we were absorbing, switch to squeezing mode
        if self.absorbing {
            self.absorbing = false;
            self.output_buffer.clear();
            self.output_pos = 0;
        }

        let mut remaining = output.len();
        let mut output_offset = 0;

        while remaining > 0 {
            // Refill output buffer if needed
            if self.output_pos >= self.output_buffer.len() {
                let hash = sha2::Sha256::digest(&self.state);
                self.output_buffer = hash.to_vec();
                self.output_pos = 0;
                // Update state for next squeeze
                self.state = hash.to_vec();
            }

            let available = self.output_buffer.len() - self.output_pos;
            let to_copy = remaining.min(available);

            output[output_offset..output_offset + to_copy]
                .copy_from_slice(&self.output_buffer[self.output_pos..self.output_pos + to_copy]);

            self.output_pos += to_copy;
            output_offset += to_copy;
            remaining -= to_copy;
        }

        self
    }

    fn ratchet_unchecked(&mut self) -> &mut Self {
        // Hash the current state to get a new state
        let hash = sha2::Sha256::digest(&self.state);
        self.state = hash.to_vec();
        self.output_buffer.clear();
        self.output_pos = 0;
        self.absorbing = true;
        self
    }
}

impl Zeroize for Sha256Sponge {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.output_buffer.zeroize();
        self.output_pos = 0;
        self.absorbing = true;
    }
}
