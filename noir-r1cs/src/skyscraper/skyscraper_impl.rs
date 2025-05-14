use {
    crate::utils::uint_to_field,
    ark_ff::{BigInt, PrimeField},
    bytemuck::bytes_of_mut,
    ruint::uint,
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    whir::crypto::fields::Field256,
    zeroize::Zeroize,
};

const RC: [Field256; 8] = [
    uint_to_field(uint!(
        17829420340877239108687448009732280677191990375576158938221412342251481978692_U256
    )),
    uint_to_field(uint!(
        5852100059362614845584985098022261541909346143980691326489891671321030921585_U256
    )),
    uint_to_field(uint!(
        17048088173265532689680903955395019356591870902241717143279822196003888806966_U256
    )),
    uint_to_field(uint!(
        71577923540621522166602308362662170286605786204339342029375621502658138039_U256
    )),
    uint_to_field(uint!(
        1630526119629192105940988602003704216811347521589219909349181656165466494167_U256
    )),
    uint_to_field(uint!(
        7807402158218786806372091124904574238561123446618083586948014838053032654983_U256
    )),
    uint_to_field(uint!(
        13329560971460034925899588938593812685746818331549554971040309989641523590611_U256
    )),
    uint_to_field(uint!(
        16971509144034029782226530622087626979814683266929655790026304723118124142299_U256
    )),
];

const SIGMA: Field256 = uint_to_field(uint!(
    9915499612839321149637521777990102151350674507940716049588462388200839649614_U256
));

const fn sbox(v: u8) -> u8 {
    (v ^ ((!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3))).rotate_left(1)
}

/// TODO: Add documentation
pub fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let limbs = bytes
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();
    BigInt::new(limbs.try_into().unwrap())
}

fn bar(a: Field256) -> Field256 {
    let mut limbs = a.into_bigint().0;
    let bytes = bytes_of_mut(&mut limbs);

    let (left, right) = bytes.split_at_mut(16);
    left.swap_with_slice(right);
    bytes.iter_mut().for_each(|b| *b = sbox(*b));

    Field256::new(BigInt(limbs))
}

fn square(a: Field256) -> Field256 {
    a * a * SIGMA
}

type State = [Field256; 2];
fn permute([l, r]: State) -> State {
    let (l, r) = (r + square(l), l);
    let (l, r) = (r + square(l) + RC[0], l);
    let (l, r) = (r + bar(l) + RC[1], l);
    let (l, r) = (r + bar(l) + RC[2], l);
    let (l, r) = (r + square(l) + RC[3], l);
    let (l, r) = (r + square(l) + RC[4], l);
    let (l, r) = (r + bar(l) + RC[5], l);
    let (l, r) = (r + bar(l) + RC[6], l);
    let (l, r) = (r + square(l) + RC[7], l);
    let (l, r) = (r + square(l), l);
    [l, r]
}

/// TODO: Add documentation
pub fn compress(l: Field256, r: Field256) -> Field256 {
    let a = l;
    let [l, _] = permute([l, r]);
    l + a
}

/// TODO: Add documentation
#[derive(Clone, Default, Zeroize)]
pub struct Skyscraper {
    state: State,
}
impl AsRef<[Field256]> for Skyscraper {
    fn as_ref(&self) -> &[Field256] {
        &self.state
    }
}

impl AsMut<[Field256]> for Skyscraper {
    fn as_mut(&mut self) -> &mut [Field256] {
        &mut self.state
    }
}

impl Permutation for Skyscraper {
    type U = Field256;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = Field256::new(bigint_from_bytes_le(&iv));
        Self {
            state: [0.into(), felt],
        }
    }

    fn permute(&mut self) {
        self.state = permute(self.state);
    }
}
/// TODO: Add documentation
pub type SkyscraperSponge = DuplexSponge<Skyscraper>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_square() {
        uint! {
            assert_eq!(square(0.into()), 0.into());
            assert_eq!(square(1.into()),
                uint_to_field(9915499612839321149637521777990102151350674507940716049588462388200839649614_U256));
            assert_eq!(square(2.into()),
                uint_to_field(17773755579518009376303681366703133516854333631346829854655645366227550102839_U256));
            assert_eq!(
                square(uint_to_field(1104450765605124869545290932753078120560901577733272073477890658487831733222_U256)),
                uint_to_field(20498050724266033890829404465405035543297153733520482423774420418741549228506_U256));
        }
    }

    #[test]
    fn test_bar() {
        uint! {
            assert_eq!(bar(0.into()), 0.into());
            assert_eq!(bar(1.into()),
                uint_to_field(680564733841876926926749214863536422912_U256.into()));
            assert_eq!(bar(2.into()),
                uint_to_field(1361129467683753853853498429727072845824_U256.into()));
            assert_eq!(
                bar(uint_to_field(4111585712030104139416666328230194227848755236259444667527487224433891325648_U256.into())),
                uint_to_field(18867677047139790809471719918880601980605904427073186248909139907505620573990_U256.into()));
        }
    }

    #[test]
    fn test_compress() {
        uint! {
            assert_eq!(compress(
                uint_to_field(21614608883591910674239883101354062083890746690626773887530227216615498812963_U256.into()),
                uint_to_field(9813154100006487150380270585621895148484502414032888228750638800367218873447_U256.into()),
            ),
            uint_to_field(3583228880285179354728993622328037400470978495633822008876840172083178912457_U256.into())
            );
        }
    }
}
