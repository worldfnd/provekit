//! Reference implementation of the Skyscraper hash function using the Field elements.
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

const RC: [U256; 8] = uint! {[
    17829420340877239108687448009732280677191990375576158938221412342251481978692_U256,
    5852100059362614845584985098022261541909346143980691326489891671321030921585_U256,
    17048088173265532689680903955395019356591870902241717143279822196003888806966_U256,
    71577923540621522166602308362662170286605786204339342029375621502658138039_U256,
    1630526119629192105940988602003704216811347521589219909349181656165466494167_U256,
    7807402158218786806372091124904574238561123446618083586948014838053032654983_U256,
    13329560971460034925899588938593812685746818331549554971040309989641523590611_U256,
    16971509144034029782226530622087626979814683266929655790026304723118124142299_U256,
]};
const SIGMA: U256 =
    uint!(9915499612839321149637521777990102151350674507940716049588462388200839649614_U256);

pub struct Skyscraper;

impl Display for Skyscraper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("skyscraper-bn254-ref")
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
    let (l, r) = (r + square(l), l);
    let (l, r) = (r + square(l) + RC[0].into(), l);
    let (l, r) = (r + bar(l) + RC[1].into(), l);
    let (l, r) = (r + bar(l) + RC[2].into(), l);
    let (l, r) = (r + square(l) + RC[3].into(), l);
    let (l, r) = (r + square(l) + RC[4].into(), l);
    let (l, r) = (r + bar(l) + RC[5].into(), l);
    let (l, r) = (r + bar(l) + RC[6].into(), l);
    let (l, r) = (r + square(l) + RC[7].into(), l);
    let (l, _) = (r + square(l), l);
    l + a
}

fn square(a: Bn254Element) -> Bn254Element {
    a.square() * SIGMA.into()
}

fn bar(a: Bn254Element) -> Bn254Element {
    // Decompose into raw bytes.
    let mut a = a.to_uint();
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
    Bn254Field.from(a)
}

fn sbox(v: u8) -> u8 {
    (v ^ ((!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3))).rotate_left(1)
}

#[cfg(test)]
mod tests {
    use {super::*, ruint::uint};

    #[test]
    fn test_sbox() {
        assert_eq!(sbox(0xcd), 0xd3);
        assert_eq!(sbox(0x17), 0x0e);
    }

    #[test]
    fn test_square() {
        uint! {
            assert_eq!(square(0_U256.into()), 0_U256.into());
            assert_eq!(square(1_U256.into()),
                9915499612839321149637521777990102151350674507940716049588462388200839649614_U256.into());
            assert_eq!(square(2_U256.into()),
                17773755579518009376303681366703133516854333631346829854655645366227550102839_U256.into());
            assert_eq!(
                square(1104450765605124869545290932753078120560901577733272073477890658487831733222_U256.into()),
                20498050724266033890829404465405035543297153733520482423774420418741549228506_U256.into());
        }
    }

    #[test]
    fn test_square_redc() {}

    #[test]
    fn test_bar() {
        uint! {
            assert_eq!(bar(0_U256.into()), 0_U256.into());
            assert_eq!(bar(1_U256.into()),
                680564733841876926926749214863536422912_U256.into());
            assert_eq!(bar(2_U256.into()),
                1361129467683753853853498429727072845824_U256.into());
            assert_eq!(
                bar(4111585712030104139416666328230194227848755236259444667527487224433891325648_U256.into()),
                18867677047139790809471719918880601980605904427073186248909139907505620573990_U256.into());
        }
    }

    #[test]
    fn test_compress() {
        uint! {
            assert_eq!(compress(
                21614608883591910674239883101354062083890746690626773887530227216615498812963_U256.into(),
                9813154100006487150380270585621895148484502414032888228750638800367218873447_U256.into(),
            ),
            3583228880285179354728993622328037400470978495633822008876840172083178912457_U256.into()
            );
        }
    }
}
