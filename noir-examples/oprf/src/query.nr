use super::{
    commitment::generate_query,
    merkle_proof::{compute_merkle_root_poseidon2, merkle_leaf},
    types::{MerkleProof, OprfQueryInputs, PublicKey},
};
use babyjubjub::{BabyJubJubPoint, hash_to_curve::encode};
use eddsa_poseidon2::verify_eddsa_poseidon2;

pub fn oprf_query_inner<let MAX_DEPTH: u32, let NUM_KEYS: u32>(
    query: Field,
    depth: Field,
    root: Field,
    inputs: OprfQueryInputs<MAX_DEPTH, NUM_KEYS>,
    beta_bits: [u1; 251],
) -> BabyJubJubPoint {
    // 1. Verify sk/pk by verifying a signature to a known message
    let chosen_pk = inputs.user_pk[inputs.pk_index as u32];

    let is_valid = verify_eddsa_poseidon2(
        chosen_pk.x,
        chosen_pk.y,
        inputs.query_s,
        inputs.query_r,
        query,
    );
    assert(is_valid, "Invalid signature");

    // Compute and verify merkle proof
    let merkle_leaf = merkle_leaf(inputs.user_pk);
    let computed_root = compute_merkle_root_poseidon2(
        merkle_leaf,
        depth,
        inputs.merkle_proof.mt_index,
        inputs.merkle_proof.siblings,
    );
    assert(computed_root == root, "Merkle proof verification failed");

    // Encode query to curve point and perform scalar multiplication
    let (px, py) = encode(query);
    let p = BabyJubJubPoint::new(px, py);
    // Precondition: encode returns a valid point on the BabyJubJub curve in the prime order subgroup
    let q = p.scalar_mul_bits(beta_bits);

    q
}

pub fn verify_unblinding(
    oprf_response: BabyJubJubPoint,
    oprf_response_blinded: BabyJubJubPoint,
    beta_bits: [u1; 251],
) {
    // Check that oprf_response is on the curve and perform unblinding
    assert(oprf_response.is_on_curve(), "OPRF response must be on curve");
    // We need to check that the response is in the prime order subgroup, otherwise the response may include a small-order component which may get canceled out during unblinding and allow malleability here
    assert(oprf_response.check_sub_group(), "OPRF response must be in prime order subgroup");

    // Verify: oprf_response * beta === oprf_response_blinded
    let reblinded = oprf_response.scalar_mul_bits(beta_bits);
    // Since response point is in the prime order subgroup, reblinded is also in the prime order subgroup.

    assert(
        (reblinded.x == oprf_response_blinded.x) & (reblinded.y == oprf_response_blinded.y),
        "Unblinding verification failed",
    );
}

pub fn oprf_query<let MAX_DEPTH: u32, let NUM_KEYS: u32>(
    depth: Field,
    root: Field,
    rp_id: Field,
    action: Field,
    nonce: Field,
    inputs: OprfQueryInputs<MAX_DEPTH, NUM_KEYS>,
) -> BabyJubJubPoint {
    // Derive the query using Poseidon4
    let query = generate_query(inputs, rp_id, action);

    // Validate beta once and reuse the bits
    assert(inputs.beta != 0, "Beta cannot be zero");
    let beta_bits = BabyJubJubPoint::validate_scalar_field_with_bits(inputs.beta);
    let result = oprf_query_inner(query, depth, root, inputs, beta_bits);

    // SAFETY: The multiplication is constrained below, this is just to emulate the signal hash coming from Circom/Semaphore
    let sqr_nonce = unsafe { unconstrained_mul(nonce, nonce) };
    assert(sqr_nonce == nonce * nonce);

    result
}

unconstrained fn unconstrained_mul(a: Field, b: Field) -> Field {
    a * b
}

#[test]
fn oprf_query_kat_test() {
    let inputs = OprfQueryInputs::<30, 7> {
        user_pk: [
            PublicKey {
                x: 19565493445664319509682066258510677837096271188915949860977009706932369175203,
                y: 19978457304613810993398911764266975074926641065301749225468860215203965473373,
            },
            PublicKey { x: 0, y: 1 },
            PublicKey { x: 0, y: 1 },
            PublicKey { x: 0, y: 1 },
            PublicKey { x: 0, y: 1 },
            PublicKey { x: 0, y: 1 },
            PublicKey { x: 0, y: 1 },
        ],
        pk_index: 0,
        query_r: [
            2935169873833602205329832148018463160341406366090112498723276323952556891709,
            15448476048961421250495083913939888960507019236416367220733727182584406690173,
        ],
        query_s: 554036835054014596689133129775275210429926310845300985076950776856375504079,
        merkle_proof: MerkleProof::<30> {
            mt_index: 0,
            siblings: [
                0,
                15621590199821056450610068202457788725601603091791048810523422053872049975191,
                15180302612178352054084191513289999058431498575847349863917170755410077436260,
                20846426933296943402289409165716903143674406371782261099735847433924593192150,
                19570709311100149041770094415303300085749902031216638721752284824736726831172,
                11737142173000203701607979434185548337265641794352013537668027209469132654026,
                11865865012735342650993929214218361747705569437250152833912362711743119784159,
                1493463551715988755902230605042557878234810673525086316376178495918903796315,
                18746103596419850001763894956142528089435746267438407061601783590659355049966,
                21234194473503024590374857258930930634542887619436018385581872843343250130100,
                14681119568252857310414189897145410009875739166689283501408363922419813627484,
                13243470632183094581890559006623686685113540193867211988709619438324105679244,
                19463898140191333844443019106944343282402694318119383727674782613189581590092,
                10565902370220049529800497209344287504121041033501189980624875736992201671117,
                5560307625408070902174028041423028597194394554482880015024167821933869023078,
                20576730574720116265513866548855226316241518026808984067485384181494744706390,
                11166760821615661136366651998133963805984915741187325490784169611245269155689,
                13692603500396323648417392244466291089928913430742736835590182936663435788822,
                11129674755567463025028188404867541558752927519269975708924528737249823830641,
                6673535049007525806710184801639542254440636510496168661971704157154828514023,
                7958154589163466663626421142270206662020519181323839780192984613274682930816,
                3739156991379607404516753076057250171966250101655747790592556040569841550790,
                1334107297020502384420211493664486465203492095766400031330900935069700302301,
                20357028769054354174264046872903423695314313082869184437966002491602414517674,
                19392290367394672558538719012722289280213395590510602524366987685302929990731,
                7360502715619830055199267117332475946442427205382059394111067387016428818088,
                9629177338475347225553791169746168712988898028547587350296027054067573957412,
                21877160135037839571797468541807904053886800340144060811298025652177410263004,
                7105691694342706282901391345307729036900705570482804586768449537652208350743,
                15888057581779748293164452094398990053773731478520540058125130669204703869637,
            ],
        },
        beta: 1219447978145766874721695300216900264892278162307712369438981445355514609028,
    };
    let rp_id: Field = 148500211659041461394599242357030289810;
    let action: Field =
        15574411524701554947159716967598594376617389345302089033983599196736786897550;
    let nonce: Field =
        21697474931205116140076044014718540540776067939642973683638014972634574223599;
    let root: Field = 14601560722057094868688356792980691747364698985297274009953072337353386968520;
    let depth = 30;

    let expected = BabyJubJubPoint::new(
        9674018812144873985515234638873635008708834681175738612597888298086191498827,
        18818965079786157878748649151755578492493325229415754584538271947197071123195,
    );

    let result = oprf_query(depth, root, rp_id, action, nonce, inputs);

    assert((result.x == expected.x) & (result.y == expected.y), "OPRF query test failed");
}
