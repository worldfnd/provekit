use {
    super::{ModRing, ModRingElement, RingRef},
    ruint::{aliases::U256, uint},
    std::ops::Deref,
};

// Marker type for Bn254 scalar field elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bn254Field;

impl RingRef for Bn254Field {
    type Uint = U256;
}

impl Deref for Bn254Field {
    type Target = ModRing<U256>;

    fn deref(&self) -> &Self::Target {
        const FIELD: ModRing<U256> = uint! {
            ModRing {
                modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617_U256,
                montgomery_r: 6350874878119819312338956282401532410528162663560392320966563075034087161851_U256,
                montgomery_r2: 944936681149208446651664254269745548490766851729442924617792859073125903783_U256,
                montgomery_r3: 5866548545943845227489894872040244720403868105578784105281690076696998248512_U256,
                mod_inv: 14042775128853446655_u64,
            }
        };
        &FIELD
    }
}

pub type Bn254Element = ModRingElement<Bn254Field>;

#[test]
fn test_bn254_field() {
    assert_eq!(size_of::<Bn254Element>(), 32);
    assert_eq!(*Bn254Field, ModRing::from_modulus(Bn254Field.modulus()));
}
