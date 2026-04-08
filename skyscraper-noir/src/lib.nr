// Skyscraper v2 Noir library (BN254)
// Exports a 2-to-1 compression hash `compress`.

// Sigma inverse constant (as in Rust/Solidity implementations)
pub global sigma_inv: Field =
    9915499612839321149637521777990102151350674507940716049588462388200839649614;

// Round constants (t=1) as an array (first and last are 0).
pub global RC: [Field; 18] = [
    0,
    17829420340877239108687448009732280677191990375576158938221412342251481978692,
    5852100059362614845584985098022261541909346143980691326489891671321030921585,
    17048088173265532689680903955395019356591870902241717143279822196003888806966,
    71577923540621522166602308362662170286605786204339342029375621502658138039,
    1630526119629192105940988602003704216811347521589219909349181656165466494167,
    7807402158218786806372091124904574238561123446618083586948014838053032654983,
    13329560971460034925899588938593812685746818331549554971040309989641523590611,
    16971509144034029782226530622087626979814683266929655790026304723118124142299,
    8608910393531852188108777530736778805001620473682472554749734455948859886057,
    10789906636021659141392066577070901692352605261812599600575143961478236801530,
    18708129585851494907644197977764586873688181219062643217509404046560774277231,
    8383317008589863184762767400375936634388677459538766150640361406080412989586,
    10555553646766747611187318546907885054893417621612381305146047194084618122734,
    18278062107303135832359716534360847832111250949377506216079581779892498540823,
    9307964587880364850754205696017897664821998926660334400055925260019288889718,
    13066217995902074168664295654459329310074418852039335279433003242098078040116,
    0,
];

// Byte S-Box as a lookup table
pub global SBOX: [u8; 256] = [
    0x00, 0x02, 0x04, 0x16, 0x08, 0x0a, 0x2c, 0x2e, 0x10, 0x12, 0x14, 0x06, 0x58, 0x5a, 0x5c, 0x5e,
    0x20, 0x22, 0x24, 0x36, 0x28, 0x2a, 0x0c, 0x0e, 0xb0, 0xb2, 0xb4, 0xa6, 0xb8, 0xba, 0xbc, 0xbe,
    0x40, 0x42, 0x44, 0x56, 0x48, 0x4a, 0x6c, 0x6e, 0x50, 0x52, 0x54, 0x46, 0x18, 0x1a, 0x1c, 0x1e,
    0x61, 0x63, 0x65, 0x77, 0x69, 0x6b, 0x4d, 0x4f, 0x71, 0x73, 0x75, 0x67, 0x79, 0x7b, 0x7d, 0x7f,
    0x80, 0x82, 0x84, 0x96, 0x88, 0x8a, 0xac, 0xae, 0x90, 0x92, 0x94, 0x86, 0xd8, 0xda, 0xdc, 0xde,
    0xa0, 0xa2, 0xa4, 0xb6, 0xa8, 0xaa, 0x8c, 0x8e, 0x30, 0x32, 0x34, 0x26, 0x38, 0x3a, 0x3c, 0x3e,
    0xc2, 0xc0, 0xc6, 0xd4, 0xca, 0xc8, 0xee, 0xec, 0xd2, 0xd0, 0xd6, 0xc4, 0x9a, 0x98, 0x9e, 0x9c,
    0xe2, 0xe0, 0xe6, 0xf4, 0xea, 0xe8, 0xce, 0xcc, 0xf2, 0xf0, 0xf6, 0xe4, 0xfa, 0xf8, 0xfe, 0xfc,
    0x01, 0x0b, 0x05, 0x17, 0x09, 0x03, 0x2d, 0x2f, 0x11, 0x1b, 0x15, 0x07, 0x59, 0x53, 0x5d, 0x5f,
    0x21, 0x2b, 0x25, 0x37, 0x29, 0x23, 0x0d, 0x0f, 0xb1, 0xbb, 0xb5, 0xa7, 0xb9, 0xb3, 0xbd, 0xbf,
    0x41, 0x4b, 0x45, 0x57, 0x49, 0x43, 0x6d, 0x6f, 0x51, 0x5b, 0x55, 0x47, 0x19, 0x13, 0x1d, 0x1f,
    0x60, 0x6a, 0x64, 0x76, 0x68, 0x62, 0x4c, 0x4e, 0x70, 0x7a, 0x74, 0x66, 0x78, 0x72, 0x7c, 0x7e,
    0x85, 0x8b, 0x81, 0x97, 0x8d, 0x83, 0xa9, 0xaf, 0x95, 0x9b, 0x91, 0x87, 0xdd, 0xd3, 0xd9, 0xdf,
    0xa5, 0xab, 0xa1, 0xb7, 0xad, 0xa3, 0x89, 0x8f, 0x35, 0x3b, 0x31, 0x27, 0x3d, 0x33, 0x39, 0x3f,
    0xc5, 0xcb, 0xc1, 0xd7, 0xcd, 0xc3, 0xe9, 0xef, 0xd5, 0xdb, 0xd1, 0xc7, 0x9d, 0x93, 0x99, 0x9f,
    0xe5, 0xeb, 0xe1, 0xf7, 0xed, 0xe3, 0xc9, 0xcf, 0xf5, 0xfb, 0xf1, 0xe7, 0xfd, 0xf3, 0xf9, 0xff,
];

// --- Helpers ---

fn square(x: Field) -> Field {
    x * x * sigma_inv
}

fn bar(x: Field) -> Field {
    let bytes: [u8; 32] = x.to_le_bytes();
    let mut acc: Field = 0;
    let mut pow: Field = 1;
    // First half: bytes[16..32]
    for i in 0..16 {
        acc += pow * SBOX[(bytes[16 + i] as u32)] as Field;
        pow *= 256;
    }
    // Second half: bytes[0..16]
    for i in 0..16 {
        acc += pow * SBOX[(bytes[i] as u32)] as Field;
        pow *= 256;
    }
    acc
}

fn ss(round: u32, mut l: Field, mut r: Field) -> (Field, Field) {
    r += square(l) + RC[round];
    l += square(r) + RC[round + 1];
    (l, r)
}

fn bb(round: u32, mut l: Field, mut r: Field) -> (Field, Field) {
    r += bar(l) + RC[round];
    l += bar(r) + RC[round + 1];
    (l, r)
}

pub fn permute(mut l: Field, mut r: Field) -> (Field, Field) {
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

// 2-to-1 compression hash
pub fn compress(l: Field, r: Field) -> Field {
    let t = l;
    let (l2, _) = permute(l, r);
    l2 + t
}

// --- Tests ---

#[test]
fn test_sbox_examples() {
    assert(SBOX[0xcd] == 0xd3);
    assert(SBOX[0x17] == 0x0e);
    assert(SBOX[0x83] == 0x17);
    assert(SBOX[0x14] == 0x28);
    assert(SBOX[0x2b] == 0x46);
    assert(SBOX[0x1e] == 0xbc);
}

#[test]
fn test_perm_zero() {
    let (l, r) = permute(0, 0);
    assert(l == 5793276905781313965269111743763131906666794041798623267477617572701829069290);
    assert(r == 12296274483727574983376829575121280934973829438414198530604912453551798647077);
}

#[test]
fn test_perm_random() {
    // Inputs from reference.rs (decimal):
    // l_original = 50417215636675310123686652273432694184389644587803328798109154235492038730484
    // r = 14620920779025509970947930308416120371903474543120179490887326852503500806990
    // Note: Noir Field literals must be < p; l_original > p, so we use l = l_original mod p.
    // This yields the same field element as reference.rs which reduces internally.
    let l = 6640729892996759679193840782918144007292915786971260110712745862340421739250; // l_original reduced mod p
    let r = 14620920779025509970947930308416120371903474543120179490887326852503500806990;
    let (el, er) = permute(l, r);
    assert(el == 8412949970293910117511617126618515787729842528183672400383899220234743146062);
    assert(er == 11868175801025513844525564200589229804433722826344843184417708742749423276015);
}
