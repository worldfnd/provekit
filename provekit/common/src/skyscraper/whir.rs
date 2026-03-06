// Use the fastest available compress_many for this platform.
#[cfg(target_arch = "aarch64")]
use skyscraper::block4::compress_many;
#[cfg(not(target_arch = "aarch64"))]
use skyscraper::simple::compress_many;
use {
    std::borrow::Cow,
    whir::{
        engines::EngineId,
        hash::{Hash, HashEngine},
    },
};

/// Pre-computed `EngineId` for the Skyscraper hash engine.
///
/// Derived as `SHA3-256("whir::hash" || "skyscraper")`.
pub const SKYSCRAPER: EngineId = EngineId::new([
    0xa5, 0x0d, 0x5e, 0xe2, 0xa3, 0xfc, 0x52, 0xe9, 0x6f, 0x11, 0x10, 0x3c, 0xbb, 0x8a, 0x65, 0xa3,
    0x77, 0xb5, 0x82, 0xb0, 0xb2, 0xdd, 0x42, 0x1c, 0x66, 0x19, 0x13, 0xe6, 0xa5, 0x63, 0xf8, 0xa1,
]);

// ============================================================================
// WHIR 2.0 HashEngine Implementation
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct SkyscraperHashEngine;

impl HashEngine for SkyscraperHashEngine {
    fn name(&self) -> Cow<'_, str> {
        "skyscraper".into()
    }

    fn supports_size(&self, size: usize) -> bool {
        size > 0 && size % 32 == 0
    }

    fn preferred_batch_size(&self) -> usize {
        skyscraper::WIDTH_LCM
    }

    fn hash_many(&self, size: usize, input: &[u8], output: &mut [Hash]) {
        assert!(
            self.supports_size(size),
            "skyscraper: unsupported message size {size} (must be a positive multiple of 32)"
        );

        let count = output.len();
        assert_eq!(
            input.len(),
            size * count,
            "skyscraper: input length {} != size {size} * count {count}",
            input.len()
        );

        // SAFETY: `output` is `&mut [[u8; 32]]` with `count` elements, so it occupies
        // exactly `count * 32` contiguous bytes. We reinterpret as a flat `&mut [u8]`
        // to interface with `compress_many` which operates on byte slices.
        let out_bytes =
            unsafe { std::slice::from_raw_parts_mut(output.as_mut_ptr().cast::<u8>(), count * 32) };

        if size == 32 {
            out_bytes.copy_from_slice(input);
            return;
        }

        if size == 64 {
            compress_many(input, out_bytes);
            return;
        }

        // Leaf hashing: left-fold 32-byte chunks, batched across messages
        // for SIMD throughput (equivalent to elements.reduce(compress)).
        // Processes in fixed-size groups to avoid heap allocation.
        const GROUP: usize = 4 * skyscraper::WIDTH_LCM; // fits in 3 KiB on stack
        let chunks_per_msg = size / 32;
        let mut pair_buf = [0u8; GROUP * 64];

        for start in (0..count).step_by(GROUP) {
            let n = (count - start).min(GROUP);
            let pairs = &mut pair_buf[..n * 64];
            let accs = &mut out_bytes[start * 32..(start + n) * 32];

            for i in 0..n {
                let msg = &input[(start + i) * size..];
                pairs[i * 64..i * 64 + 32].copy_from_slice(&msg[..32]);
                pairs[i * 64 + 32..i * 64 + 64].copy_from_slice(&msg[32..64]);
            }
            compress_many(pairs, accs);

            for k in 2..chunks_per_msg {
                for i in 0..n {
                    let msg = &input[(start + i) * size..];
                    pairs[i * 64..i * 64 + 32].copy_from_slice(&accs[i * 32..i * 32 + 32]);
                    pairs[i * 64 + 32..i * 64 + 64].copy_from_slice(&msg[k * 32..k * 32 + 32]);
                }
                compress_many(pairs, accs);
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use {super::*, zerocopy::IntoBytes};

    fn limbs_to_bytes(limbs: [u64; 4]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&limbs[0].to_le_bytes());
        out[8..16].copy_from_slice(&limbs[1].to_le_bytes());
        out[16..24].copy_from_slice(&limbs[2].to_le_bytes());
        out[24..32].copy_from_slice(&limbs[3].to_le_bytes());
        out
    }

    #[test]
    fn engine_id_matches() {
        use whir::engines::Engine;
        assert_eq!(SkyscraperHashEngine.engine_id(), SKYSCRAPER);
    }

    #[test]
    fn supports_expected_sizes() {
        let e = SkyscraperHashEngine;
        assert!(!e.supports_size(0));
        assert!(!e.supports_size(1));
        assert!(!e.supports_size(31));
        assert!(e.supports_size(32));
        assert!(e.supports_size(64));
        assert!(e.supports_size(512));
        assert!(e.supports_size(1024));
    }

    #[test]
    fn two_to_one_matches_simple_compress() {
        let l: [u64; 4] = [1, 2, 3, 4];
        let r: [u64; 4] = [5, 6, 7, 8];
        let expected = skyscraper::simple::compress(l, r);

        let mut input = [0u8; 64];
        input[0..32].copy_from_slice(&limbs_to_bytes(l));
        input[32..64].copy_from_slice(&limbs_to_bytes(r));

        let mut output = [Hash::default()];
        SkyscraperHashEngine.hash_many(64, &input, &mut output);

        assert_eq!(output[0].0, limbs_to_bytes(expected));
    }

    #[test]
    fn leaf_hash_matches_fold() {
        let elems: [[u64; 4]; 4] = [[1, 0, 0, 0], [2, 0, 0, 0], [3, 0, 0, 0], [4, 0, 0, 0]];

        let expected = elems
            .into_iter()
            .reduce(skyscraper::simple::compress)
            .unwrap();

        let mut output = [Hash::default()];
        SkyscraperHashEngine.hash_many(128, elems.as_bytes(), &mut output);

        assert_eq!(output[0].0, limbs_to_bytes(expected));
    }

    #[test]
    fn batch_two_to_one_consistency() {
        let pairs: [[[u64; 4]; 2]; 3] = [
            [[1, 2, 3, 4], [5, 6, 7, 8]],
            [[9, 10, 11, 12], [13, 14, 15, 16]],
            [[17, 18, 19, 20], [21, 22, 23, 24]],
        ];

        let mut batch_output = [Hash::default(); 3];
        SkyscraperHashEngine.hash_many(64, pairs.as_bytes(), &mut batch_output);

        for (i, pair) in pairs.iter().enumerate() {
            let expected = skyscraper::simple::compress(pair[0], pair[1]);
            assert_eq!(batch_output[i].0, limbs_to_bytes(expected));
        }
    }

    #[test]
    fn batch_leaf_hash_consistency() {
        // 3 messages of 16 field elements each (512 bytes per message).
        // Verify batched result matches per-message scalar reduce(compress).
        let msgs: [[[u64; 4]; 16]; 3] =
            std::array::from_fn(|i| std::array::from_fn(|j| [(i * 16 + j + 1) as u64, 0, 0, 0]));

        let mut batch_output = [Hash::default(); 3];
        SkyscraperHashEngine.hash_many(512, msgs.as_bytes(), &mut batch_output);

        for (i, msg) in msgs.iter().enumerate() {
            let expected = msg
                .iter()
                .copied()
                .reduce(skyscraper::simple::compress)
                .unwrap();
            assert_eq!(batch_output[i].0, limbs_to_bytes(expected));
        }
    }
}
