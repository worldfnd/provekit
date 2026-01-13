// SHA256 sponge for Fiat-Shamir transcripts
//
// This module provides a SHA256-based duplex sponge construction
// that can be used for Fiat-Shamir transformations in WHIR proofs.

use {sha2::Digest, spongefish::duplex_sponge::DuplexSpongeInterface, zeroize::Zeroize};

/// SHA256 duplex sponge for Fiat-Shamir transcripts.
///
/// Uses SHA256 as the underlying hash function with a simple sponge
/// construction. Optimized with fixed-size buffers to avoid allocations.
#[derive(Clone)]
pub struct Sha256Sponge {
    /// Current state buffer (dynamically sized during absorb phase)
    state:         Vec<u8>,
    /// Length of valid data in state
    state_len:     usize,
    /// Mode: true = absorbing, false = squeezing
    absorbing:     bool,
    /// Output buffer for squeezing (32 bytes = SHA256 output size)
    output_buffer: [u8; 32],
    /// Position in output buffer
    output_pos:    usize,
}

impl Default for Sha256Sponge {
    fn default() -> Self {
        Self {
            state:         Vec::with_capacity(256), // Pre-allocate to avoid resizes
            state_len:     0,
            absorbing:     true,
            output_buffer: [0u8; 32],
            output_pos:    32, // Force refill on first squeeze
        }
    }
}

impl DuplexSpongeInterface<u8> for Sha256Sponge {
    fn new(iv: [u8; 32]) -> Self {
        let mut state = Vec::with_capacity(256);
        state.extend_from_slice(&iv);
        Self {
            state,
            state_len: 32,
            absorbing: true,
            output_buffer: [0u8; 32],
            output_pos: 32,
        }
    }

    fn absorb_unchecked(&mut self, input: &[u8]) -> &mut Self {
        // If we were squeezing, finalize that phase
        if !self.absorbing {
            // Ratchet: hash the current state
            let hash = sha2::Sha256::digest(&self.state[..self.state_len]);
            self.state.clear();
            self.state.extend_from_slice(&hash);
            self.state_len = 32;
            self.output_pos = 32;
            self.absorbing = true;
        }

        // Absorb new input (Vec still used for variable-length absorb)
        if self.state.len() < self.state_len + input.len() {
            self.state.reserve(input.len());
        }
        self.state.extend_from_slice(input);
        self.state_len += input.len();
        self
    }

    fn squeeze_unchecked(&mut self, output: &mut [u8]) -> &mut Self {
        // If we were absorbing, switch to squeezing mode
        if self.absorbing {
            self.absorbing = false;
            self.output_pos = 32; // Force refill
        }

        let mut remaining = output.len();
        let mut output_offset = 0;

        while remaining > 0 {
            // Refill output buffer if needed
            if self.output_pos >= 32 {
                let hash = sha2::Sha256::digest(&self.state[..self.state_len]);
                self.output_buffer.copy_from_slice(&hash);
                self.output_pos = 0;
                // Update state for next squeeze
                self.state.clear();
                self.state.extend_from_slice(&hash);
                self.state_len = 32;
            }

            let available = 32 - self.output_pos;
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
        let hash = sha2::Sha256::digest(&self.state[..self.state_len]);
        self.state.clear();
        self.state.extend_from_slice(&hash);
        self.state_len = 32;
        self.output_pos = 32;
        self.absorbing = true;
        self
    }
}

impl Zeroize for Sha256Sponge {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.state_len = 0;
        self.output_buffer.zeroize();
        self.output_pos = 32;
        self.absorbing = true;
    }
}
