use {
    crate::{
        mod_ring::{
            fields::{Bn254Element, Bn254Field},
            RingRefExt,
        },
        SmolHasher,
    },
    ruint::{aliases::U256, uint},
    std::fmt::Display,
};

const RC: [Bn254Element; 8] = [
    Bn254Element::from_montgomery(Bn254Field, U256::ZERO),
    Bn254Element::from_montgomery(Bn254Field, U256::ZERO),
    Bn254Element::from_montgomery(Bn254Field, U256::ZERO),
    Bn254Element::from_montgomery(Bn254Field, U256::ZERO),
    Bn254Element::from_montgomery(Bn254Field, U256::ZERO),
    Bn254Element::from_montgomery(Bn254Field, U256::ZERO),
    Bn254Element::from_montgomery(Bn254Field, U256::ZERO),
    Bn254Element::from_montgomery(Bn254Field, U256::ZERO),
];

pub struct Skyscraper;

const MODULUS4: U256 =
    uint!(0xc19139cb84c680a6e14116da06056174a0cfa121e6e5c2450f87d64fc0000004_U256);
const MODULUS2: U256 =
    uint!(0x60c89ce5c263405370a08b6d0302b0ba5067d090f372e12287c3eb27e0000002_U256);

impl Display for Skyscraper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("skyscraper-bn254-ruint")
    }
}

impl SmolHasher for Skyscraper {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let a = from_bytes(&message[0..32]);
            let b = from_bytes(&message[32..64]);
            let c = compress(a, b);
            hash.copy_from_slice(c.as_montgomery().as_le_slice());
        }
    }
}

fn from_bytes(bytes: &[u8]) -> Bn254Element {
    let mut bytes: [u8; 32] = bytes.try_into().unwrap();
    bytes[31] = 0;
    Bn254Field.from_montgomery(U256::from_le_bytes::<32>(bytes))
}

fn compress(l: Bn254Element, r: Bn254Element) -> Bn254Element {
    let a = l;
    let (l, r) = (r + l.square(), l);
    let (l, r) = (r + l.square() + RC[0], l);
    let (l, r) = (r + bar(l) + RC[1], l);
    let (l, r) = (r + bar(l) + RC[2], l);
    let (l, r) = (r + l.square() + RC[3], l);
    let (l, r) = (r + l.square() + RC[4], l);
    let (l, r) = (r + bar(l) + RC[5], l);
    let (l, r) = (r + bar(l) + RC[6], l);
    let (l, r) = (r + l.square() + RC[7], l);
    let (l, _) = (r + l.square(), l);
    l + a
}

fn bar(a: Bn254Element) -> Bn254Element {
    // Decompose into raw bytes of the Montgomery form.
    let mut a = a.as_montgomery();
    let bytes = unsafe { a.as_le_slice_mut() };

    // Cyclic rotate by 16 bytes.
    let (left, right) = bytes.split_at_mut(16);
    left.swap_with_slice(right);

    // Apply SBox.
    bytes.iter_mut().for_each(|b| *b = sbox(*b));

    // Recompose and modular reduce
    while a > Bn254Field.modulus() {
        a -= Bn254Field.modulus();
    }
    Bn254Field.from_montgomery(a)
}

fn sbox(v: u8) -> u8 {
    (v ^ ((!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3))).rotate_left(1)
}

#[test]
fn test_sbox() {
    assert_eq!(sbox(0xcd), 0xd3);
    assert_eq!(sbox(0x17), 0x0e);
}
