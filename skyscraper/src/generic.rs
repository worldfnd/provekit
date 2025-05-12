use {
    crate::{
        arithmetic::{addv, less_than},
        bar::barv,
        reduce::{reduce, reduce_partial, reduce_partial_add_rcv},
    },
    std::sync::atomic::{AtomicU64, Ordering},
    zerocopy::{FromBytes, IntoBytes},
};

/// Generic single-threaded batch compression.
///
/// Requires an N-way two-to-one hash function `compress`.
pub fn compress_many<F, const N: usize>(compress: F, messages: &[u8], hashes: &mut [u8])
where
    F: Fn([[[u64; 4]; 2]; N]) -> [[u64; 4]; N],
{
    assert_eq!(messages.len() % 64, 0);
    assert_eq!(hashes.len() % 32, 0);
    assert_eq!(hashes.len() * 2, messages.len());
    let count = hashes.len() / 32;
    let tail = count % N;
    let blocks = count - tail;
    let (msg_blocks, msg_tail) = messages.split_at(blocks * 64);
    let (hsh_blocks, hsh_tail) = hashes.split_at_mut(blocks * 32);
    for (message, hash) in msg_blocks
        .chunks_exact(64 * N)
        .zip(hsh_blocks.chunks_exact_mut(32 * N))
    {
        let input = <[[[u64; 4]; 2]; N]>::read_from_bytes(message).unwrap();
        let h = compress(input);
        hash.copy_from_slice(h.as_bytes());
    }
    if tail > 0 {
        let mut input = [[[0_u64; 4]; 2]; N];
        for (i, msg) in msg_tail.chunks_exact(64).enumerate() {
            input[i] = <[[u64; 4]; 2]>::read_from_bytes(msg).unwrap();
        }
        let h = compress(input);
        hsh_tail.copy_from_slice(&h.as_bytes()[..tail * 32]);
    }
}

/// Generic multi-threaded proof of work solver.
///
/// Requires an N-way two-to-one hash function `compress`.
pub fn solve<F, const N: usize>(compress_many: F, challenge: [u64; 4], threshold: [u64; 4]) -> u64
where
    F: Fn(&[u8], &mut [u8]) + Send + Sync,
{
    let best = AtomicU64::new(u64::MAX);
    rayon::broadcast(|ctx| {
        let mut input = [[challenge, [0; 4]]; N];
        let mut hashes = [[0; 4]; N];
        for nonce in (0..)
            .step_by(N)
            .skip(ctx.index())
            .step_by(ctx.num_threads())
        {
            if nonce > best.load(Ordering::Acquire) {
                return;
            }
            for (i, input) in input.iter_mut().enumerate() {
                input[1][0] = nonce + i as u64;
            }
            compress_many(input.as_bytes(), hashes.as_mut_bytes());
            for (i, hash) in hashes.into_iter().enumerate() {
                if less_than(hash, threshold) {
                    best.fetch_min(nonce + i as u64, Ordering::AcqRel);
                    return;
                }
            }
        }
    });
    best.load(Ordering::Acquire)
}

#[inline(always)]
pub fn compress<F, const N: usize>(square: F, input: [[[u64; 4]; 2]; N]) -> [[u64; 4]; N]
where
    F: Fn([[u64; 4]; N]) -> [[u64; 4]; N],
{
    let l = input.map(|e| e[0]).map(reduce_partial);
    let r = input.map(|e| e[1]).map(reduce_partial);
    let t = l;
    let (l, r) = (addv(r, square(l)).map(reduce_partial), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 1), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 2), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 3), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 4), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 5), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, barv(l)), 6), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, barv(l)), 7), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 8), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 9), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, barv(l)), 10), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, barv(l)), 11), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 12), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 13), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 14), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 15), l);
    let (l, r) = (reduce_partial_add_rcv(addv(r, square(l)), 16), l);
    addv(addv(r, square(l)), t).map(reduce)
}
