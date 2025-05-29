//! Reference implementation of the Skyscraper hash function using ark-ff.

use {
    ark_bn254::Fr,
    ark_ff::{BigInt, Field, PrimeField},
    seq_macro::seq,
    std::{mem::swap, sync::LazyLock},
    zerocopy::transmute,
};

// Compile time convert round constants to Fr
seq!(I in 0..18 {
    const ROUND_CONSTANTS: [Fr; 18] = [
        #(Fr::new(BigInt(crate::constants::ROUND_CONSTANTS[I])), )*
    ];
});

/// ```python
/// load('skyscraper.sage')
/// Sky_BN254_1.sigma_inv
/// ```
static SIGMA_INV: LazyLock<Fr> = LazyLock::new(|| {
    "9915499612839321149637521777990102151350674507940716049588462388200839649614"
        .parse()
        .expect("valid field element")
});

pub fn compress_many(messages: &[u8], hashes: &mut [u8]) {
    assert_eq!(messages.len() % 64, 0);
    assert_eq!(hashes.len() % 32, 0);
    assert_eq!(messages.len(), hashes.len() * 2);
    for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
        let message: [u8; 64] = message.try_into().unwrap();
        let [l, r] = transmute!(message);
        let h = compress(l, r);
        let h: [u8; 32] = transmute!(h);
        hash.copy_from_slice(h.as_slice());
    }
}

pub fn compress(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    let (l, r) = (Fr::new(BigInt(l)), Fr::new(BigInt(r)));
    let t = l;
    let (l, _) = permute(l, r);
    (l + t).into_bigint().0
}

/// See Figure 2.a
pub fn permute(l: Fr, r: Fr) -> (Fr, Fr) {
    let (l, r) = ss(0, l, r);
    let (l, r) = ss(2, l, r);
    let (l, r) = ss(4, l, r);
    let (l, r) = bb(6, l, r);
    let (l, r) = ss(8, l, r);
    let (l, r) = bb(10, l, r);
    let (l, r) = ss(12, l, r);
    let (l, r) = ss(14, l, r);
    let (l, r) = ss(16, l, r);
    (l, r)
}

/// See Figure 2.b
fn ss(round: usize, mut l: Fr, mut r: Fr) -> (Fr, Fr) {
    r += l.square() * *SIGMA_INV + ROUND_CONSTANTS[round];
    swap(&mut l, &mut r);
    r += l.square() * *SIGMA_INV + ROUND_CONSTANTS[round + 1];
    swap(&mut l, &mut r);
    (l, r)
}

/// See Figure 2.c
fn bb(round: usize, mut l: Fr, mut r: Fr) -> (Fr, Fr) {
    r += bar(l) + ROUND_CONSTANTS[round];
    swap(&mut l, &mut r);
    r += bar(l) + ROUND_CONSTANTS[round + 1];
    swap(&mut l, &mut r);
    (l, r)
}

fn bar(x: Fr) -> Fr {
    // Convert to little-endian bytes
    let limbs: [u64; 4] = x.into_bigint().0;
    let mut bytes: [u8; 32] = transmute!(limbs);

    // Cyclic rotate bytes by 16
    let (l, r) = bytes.split_at_mut(16);
    l.swap_with_slice(r);

    // Apply sbox to each byte
    let bytes = bytes.map(sbox);

    // Interpret as field element
    Fr::from_le_bytes_mod_order(bytes.as_slice())
}

pub fn sbox(v: u8) -> u8 {
    (v ^ ((!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3))).rotate_left(1)
}

#[cfg(test)]
mod tests {
    use {super::*, ark_ff::AdditiveGroup};

    #[test]
    fn test_ss_2() {
        // Example from sage reference
        let l = "11818428481613126259506041491792444971306025298632020312923851211664140080269"
            .parse()
            .unwrap();
        let r = "16089984100220651117533376273482359701319211672522891227502963383930673183481"
            .parse()
            .unwrap();
        let el = "2897520731550929941842826131888578795995028656093850302425034320680216166225"
            .parse()
            .unwrap();
        let er = "10274752619072178425540318899508997829349102488123199431506343228471746115261"
            .parse()
            .unwrap();
        let (l, r) = ss(2, l, r);
        assert_eq!(l, el);
        assert_eq!(r, er);
    }

    #[test]
    fn test_sbox() {
        // Table 3.
        assert_eq!(sbox(0xcd), 0xd3);
        assert_eq!(sbox(0x17), 0x0e);
        assert_eq!(sbox(0x83), 0x17);
        assert_eq!(sbox(0x14), 0x28);
        assert_eq!(sbox(0x2b), 0x46);
        assert_eq!(sbox(0x1e), 0xbc);
    }

    #[test]
    fn test_bb_6() {
        let l = "13251711941470795978907268022756015766767985221093713388330058285942871890923"
            .parse()
            .unwrap();
        let r = "1017722258958995329580328739423576514309327442471989504101393158056883989572"
            .parse()
            .unwrap();
        let el = "3193610555912363022088172260048956988022957239290210718020144819371540058981"
            .parse()
            .unwrap();
        let er = "17363210535454321713488811303876243393424286347736908007836172565366081010820"
            .parse()
            .unwrap();
        let (l, r) = bb(6, l, r);
        assert_eq!(l, el);
        assert_eq!(r, er);
    }

    #[test]
    fn test_zero() {
        // From Sage notebook example
        let l = Fr::ZERO;
        let r = Fr::ZERO;
        let el = "5793276905781313965269111743763131906666794041798623267477617572701829069290"
            .parse()
            .unwrap();
        let er = "12296274483727574983376829575121280934973829438414198530604912453551798647077"
            .parse()
            .unwrap();
        let (l, r) = permute(l, r);
        assert_eq!(l, el);
        assert_eq!(r, er);
    }

    #[test]
    fn test_random() {
        // From Sage notebook example
        let l = "50417215636675310123686652273432694184389644587803328798109154235492038730484"
            .parse()
            .unwrap();
        let r = "14620920779025509970947930308416120371903474543120179490887326852503500806990"
            .parse()
            .unwrap();
        let el = "8412949970293910117511617126618515787729842528183672400383899220234743146062"
            .parse()
            .unwrap();
        let er = "11868175801025513844525564200589229804433722826344843184417708742749423276015"
            .parse()
            .unwrap();
        let (l, r) = permute(l, r);
        assert_eq!(l, el);
        assert_eq!(r, er);
    }
}
