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
    let messages =
        <[[[u64; 4]; 2]]>::ref_from_bytes(messages).expect("Message length not a multiple of 64");
    let hashes = <[[u64; 4]]>::mut_from_bytes(hashes).expect("Hashes length not a multiple of 32");
    assert_eq!(
        messages.len(),
        hashes.len(),
        "Messages and hashes length mismatch"
    );
    for (message, hash) in messages.chunks(N).zip(hashes.chunks_mut(N)) {
        if message.len() == N {
            let hashes = compress(message.try_into().unwrap());
            hash.copy_from_slice(hashes.as_slice());
        } else {
            let mut input = [[[0_u64; 4]; 2]; N];
            input[..message.len()].copy_from_slice(message);
            let output = compress(input);
            hash.copy_from_slice(&output[..message.len()]);
        }
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
