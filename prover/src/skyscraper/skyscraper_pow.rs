use ruint::aliases::U256;
use ruint_macro::uint;
use spongefish_pow::PowStrategy;
use whir::crypto::fields::Field256;
use crate::skyscraper::skyscraper::{
    bigint_from_bytes_le,
    compress,
    uint_to_field,
};

/// Skyscraper proof of work
#[derive(Clone, Copy)]
pub struct SkyscraperPoW {
    challenge: Field256,
    threshold: Field256,
}

const D0 : Field256 = uint_to_field(uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256));
const D1 : Field256  = uint_to_field(uint!(10944121435919637611123202872628637544274182200208017171849102093287904247808_U256));
const D2 : Field256  = uint_to_field(uint!(5472060717959818805561601436314318772137091100104008585924551046643952123904_U256));
const D3 : Field256  = uint_to_field(uint!(2736030358979909402780800718157159386068545550052004292962275523321976061952_U256));
const D4 : Field256  = uint_to_field(uint!(1368015179489954701390400359078579693034272775026002146481137761660988030976_U256));
const D5 : Field256  = uint_to_field(uint!(684007589744977350695200179539289846517136387513001073240568880830494015488_U256));
const D6 : Field256  = uint_to_field(uint!(342003794872488675347600089769644923258568193756500536620284440415247007744_U256));
const D7 : Field256  = uint_to_field(uint!(171001897436244337673800044884822461629284096878250268310142220207623503872_U256));
const D8 : Field256  = uint_to_field(uint!(85500948718122168836900022442411230814642048439125134155071110103811751936_U256));
const D9 : Field256  = uint_to_field(uint!(42750474359061084418450011221205615407321024219562567077535555051905875968_U256));
const D10 : Field256 = uint_to_field(uint!(21375237179530542209225005610602807703660512109781283538767777525952937984_U256));
const D11 : Field256 = uint_to_field(uint!(10687618589765271104612502805301403851830256054890641769383888762976468992_U256));
const D12 : Field256 = uint_to_field(uint!(5343809294882635552306251402650701925915128027445320884691944381488234496_U256));
const D13 : Field256 = uint_to_field(uint!(2671904647441317776153125701325350962957564013722660442345972190744117248_U256));
const D14 : Field256 = uint_to_field(uint!(1335952323720658888076562850662675481478782006861330221172986095372058624_U256));
const D15 : Field256 = uint_to_field(uint!(667976161860329444038281425331337740739391003430665110586493047686029312_U256));
const D16 : Field256 = uint_to_field(uint!(333988080930164722019140712665668870369695501715332555293246523843014656_U256));
const D17 : Field256 = uint_to_field(uint!(166994040465082361009570356332834435184847750857666277646623261921507328_U256));
const D18 : Field256 = uint_to_field(uint!(83497020232541180504785178166417217592423875428833138823311630960753664_U256));
const D19 : Field256 = uint_to_field(uint!(41748510116270590252392589083208608796211937714416569411655815480376832_U256));
const D20 : Field256 = uint_to_field(uint!(20874255058135295126196294541604304398105968857208284705827907740188416_U256));
const D21 : Field256 = uint_to_field(uint!(10437127529067647563098147270802152199052984428604142352913953870094208_U256));
const D22 : Field256 = uint_to_field(uint!(5218563764533823781549073635401076099526492214302071176456976935047104_U256));
const D23 : Field256 = uint_to_field(uint!(2609281882266911890774536817700538049763246107151035588228488467523552_U256));
const D24 : Field256 = uint_to_field(uint!(1304640941133455945387268408850269024881623053575517794114244233761776_U256));
const D25 : Field256 = uint_to_field(uint!(652320470566727972693634204425134512440811526787758897057122116880888_U256));
const D26 : Field256 = uint_to_field(uint!(326160235283363986346817102212567256220405763393879448528561058440444_U256));
const D27 : Field256 = uint_to_field(uint!(163080117641681993173408551106283628110202881696939724264280529220222_U256));

const DIFFICULTY_ARRAY: [Field256; 28] = [
    D0, D1, D2, D3, D4, D5, D6, D7, D8, D9,
    D10, D11, D12, D13, D14, D15, D16, D17, D18, D19,
    D20, D21, D22, D23, D24, D25, D26, D27,
];

impl PowStrategy for SkyscraperPoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        let threshold = bits.ceil() as usize;

        Self {
            challenge: Field256::new(bigint_from_bytes_le(&challenge)),
            threshold: DIFFICULTY_ARRAY[threshold],
        }
    }


    fn check(&mut self, nonce: u64) -> bool {
        let res = compress(
            self.challenge, 
            uint_to_field(U256::from(nonce)));
        res < self.threshold
    }

    fn solve(&mut self) -> Option<u64> {
        (0u64..)
            .step_by(1)
            .find_map(|nonce| self.check_single(nonce))
    }
}


impl SkyscraperPoW {
    fn check_single(&mut self, nonce: u64) -> Option<u64> {
        let res = compress(
            self.challenge,
            uint_to_field(U256::from(nonce)));
        if res < self.threshold {
           return Some(nonce)
        }
        None
    }
}

#[test]
fn test_pow_skyscraper() {
    use spongefish_pow::{PoWChallenge, PoWDomainSeparator};
    use spongefish::{ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, DefaultHash, DomainSeparator};

    const BITS: f64 = 10.0;

    let iopattern = DomainSeparator::<DefaultHash>::new("the proof of work lottery 🎰")
        .add_bytes(1, "something")
        .challenge_pow("rolling dices");

    let mut prover = iopattern.to_prover_state();
    prover.add_bytes(b"\0").expect("Invalid IOPattern");
    prover.challenge_pow::<SkyscraperPoW>(BITS).unwrap();

    let mut verifier = iopattern.to_verifier_state(prover.narg_string());
    let byte = verifier.next_bytes::<1>().unwrap();
    assert_eq!(&byte, b"\0");
    verifier.challenge_pow::<SkyscraperPoW>(BITS).unwrap();
}