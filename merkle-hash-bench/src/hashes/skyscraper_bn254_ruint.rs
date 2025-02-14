use {
    crate::{register_hash, Field, HashFn, SmolHasher},
    hex_literal::hex,
    ruint::{aliases::U256, uint},
};

register_hash!(Skyscraper);

const MODULUS: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);
const MOD_INV: u64 = 14042775128853446655;
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
/// SBOX lookup table. Not used as computing appears fasster.
const _SBOX: [u8; 256] = hex!("00020416080a2c2e10121406585a5c5e20222436282a0c0eb0b2b4a6b8babcbe40424456484a6c6e50525446181a1c1e61636577696b4d4f71737567797b7d7f80828496888aacae90929486d8dadcdea0a2a4b6a8aa8c8e30323426383a3c3ec2c0c6d4cac8eeecd2d0d6c49a989e9ce2e0e6f4eae8ceccf2f0f6e4faf8fefc010b051709032d2f111b150759535d5f212b253729230d0fb1bbb5a7b9b3bdbf414b455749436d6f515b554719131d1f606a647668624c4e707a746678727c7e858b81978d83a9af959b9187ddd3d9dfa5aba1b7ada3898f353b31273d33393fc5cbc1d7cdc3e9efd5dbd1c79d93999fe5ebe1f7ede3c9cff5fbf1e7fdf3f9ff");

pub struct Skyscraper;

impl SmolHasher for Skyscraper {
    fn hash_fn(&self) -> HashFn {
        HashFn::Skyscraper(1)
    }

    fn implementation(&self) -> &str {
        "reference"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let a = from_bytes(&message[0..32]);
            let b = from_bytes(&message[32..64]);
            let c = compress(a, b);
            hash.copy_from_slice(c.as_le_slice());
        }
    }
}

fn from_bytes(bytes: &[u8]) -> U256 {
    reduce(U256::from_le_bytes::<32>(bytes.try_into().unwrap()))
}

const fn reduce(mut n: U256) -> U256 {
    loop {
        let (reduced, borrow) = n.overflowing_sub(MODULUS);
        if borrow {
            return n;
        } else {
            n = reduced;
        }
    }
}

const fn add_2(a: U256, b: U256) -> U256 {
    let (sum, carry) = a.overflowing_add(b);
    let (reduced, borrow) = sum.overflowing_sub(MODULUS);
    if carry | !borrow {
        reduced
    } else {
        sum
    }
}

const fn add_3(a: U256, b: U256, c: U256) -> U256 {
    add_2(add_2(a, b), c)
}

fn compress(l: U256, r: U256) -> U256 {
    let a = l;
    let (l, r) = (add_2(r, square(l)), l);
    let (l, r) = (add_3(r, square(l), RC[0]), l);
    let (l, r) = (add_3(r, bar(l), RC[1]), l);
    let (l, r) = (add_3(r, bar(l), RC[2]), l);
    let (l, r) = (add_3(r, square(l), RC[3]), l);
    let (l, r) = (add_3(r, square(l), RC[4]), l);
    let (l, r) = (add_3(r, bar(l), RC[5]), l);
    let (l, r) = (add_3(r, bar(l), RC[6]), l);
    let (l, r) = (add_3(r, square(l), RC[7]), l);
    let (l, _) = (add_2(r, square(l)), l);
    add_2(l, a)
}

fn square(n: U256) -> U256 {
    n.square_redc(MODULUS, MOD_INV)
}

fn bar(mut n: U256) -> U256 {
    // Decompose into raw bytes.
    let bytes = unsafe { n.as_le_slice_mut() };

    // Cyclic rotate by 16 bytes.
    let (left, right) = bytes.split_at_mut(16);
    left.swap_with_slice(right);

    // Apply SBox.
    bytes.iter_mut().for_each(|b| *b = sbox(*b));

    // Recompose and modular reduce
    reduce(n)
}

const fn sbox(v: u8) -> u8 {
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
            assert_eq!(square(0_U256), 0_U256);
            assert_eq!(square(1_U256),
                9915499612839321149637521777990102151350674507940716049588462388200839649614_U256);
            assert_eq!(square(2_U256),
                17773755579518009376303681366703133516854333631346829854655645366227550102839_U256);
            assert_eq!(
                square(1104450765605124869545290932753078120560901577733272073477890658487831733222_U256),
                20498050724266033890829404465405035543297153733520482423774420418741549228506_U256);
        }
    }

    #[test]
    fn test_bar() {
        uint! {
            assert_eq!(bar(0_U256), 0_U256);
            assert_eq!(bar(1_U256),
                680564733841876926926749214863536422912_U256);
            assert_eq!(bar(2_U256),
                1361129467683753853853498429727072845824_U256);
            assert_eq!(
                bar(4111585712030104139416666328230194227848755236259444667527487224433891325648_U256),
                18867677047139790809471719918880601980605904427073186248909139907505620573990_U256);
        }
    }

    #[test]
    fn test_compress() {
        uint! {
            assert_eq!(compress(
                21614608883591910674239883101354062083890746690626773887530227216615498812963_U256,
                9813154100006487150380270585621895148484502414032888228750638800367218873447_U256,
            ),
            3583228880285179354728993622328037400470978495633822008876840172083178912457_U256
            );
        }
    }
}
