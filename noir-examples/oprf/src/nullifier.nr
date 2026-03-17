use super::{
    commitment::{generate_commitment, generate_query},
    credential_signature::check_credential_signature,
    dlog::verify_dlog_equality,
    query::{oprf_query_inner, verify_unblinding},
    types::{MerkleProof, OprfNullifierInputs, OprfNullifierOutputs, OprfQueryInputs, PublicKey},
};

use babyjubjub::BabyJubJubPoint;

pub fn oprf_nullifier<let MAX_DEPTH: u32, let NUM_KEYS: u32>(
    cred_pk: PublicKey,
    current_timestamp: u64,
    cred_genesis_issued_at_min: u64,
    root: Field,
    depth: Field,
    rp_id: Field,
    action: Field,
    oprf_pk: PublicKey,
    signal_hash: Field,
    nonce: Field,
    inputs: OprfNullifierInputs<MAX_DEPTH, NUM_KEYS>,
) -> OprfNullifierOutputs {
    // Derive the query using Poseidon4
    let query = generate_query(inputs.query_inputs, rp_id, action);

    // Validate beta once and reuse the bits
    assert(inputs.query_inputs.beta != 0, "Beta cannot be zero");
    let beta_bits = BabyJubJubPoint::validate_scalar_field_with_bits(inputs.query_inputs.beta);

    // 1-2. Show that the original query was computed correctly
    let oprf_query_key = oprf_query_inner(query, depth, root, inputs.query_inputs, beta_bits);

    // 3. Verify credential signature
    check_credential_signature(
        inputs.cred_s,
        inputs.cred_r,
        [cred_pk.x, cred_pk.y],
        inputs.issuer_schema_id,
        inputs.query_inputs.merkle_proof.mt_index,
        inputs.cred_user_id_r,
        inputs.cred_genesis_issued_at,
        inputs.cred_expires_at,
        [inputs.cred_hashes.claims_hash, inputs.cred_hashes.associated_data_hash],
        current_timestamp,
        cred_genesis_issued_at_min,
        inputs.cred_id,
    );

    // 4. Check the dlog equality proof
    let oprf_pk = BabyJubJubPoint::new(oprf_pk.x, oprf_pk.y);
    verify_dlog_equality(
        inputs.dlog_e,
        inputs.dlog_s,
        oprf_pk,
        oprf_query_key,
        inputs.oprf_response_blinded,
    );

    // 5. Verify that the user unblinded correctly
    // This checks that: oprf_response * beta === oprf_response_blinded
    verify_unblinding(
        inputs.oprf_response,
        inputs.oprf_response_blinded,
        beta_bits,
    );

    // Generate commitment and nullifier using the unblinded oprf_response
    let outputs = generate_commitment(
        query,
        inputs.oprf_response,
        inputs.query_inputs.merkle_proof.mt_index,
        inputs.id_commitment_r,
    );

    // SAFETY: The multiplication is constrained below, this is just to emulate the signal hash coming from Circom/Semaphore
    let sqr_nonce = unsafe { unconstrained_mul(nonce, nonce) };
    assert(sqr_nonce == nonce * nonce);
    // SAFETY: The multiplication is constrained below, this is just to emulate the signal hash coming from Circom/Semaphore
    let sqr_signal_hash = unsafe { unconstrained_mul(signal_hash, signal_hash) };
    assert(sqr_signal_hash == signal_hash * signal_hash);

    outputs
}

unconstrained fn unconstrained_mul(a: Field, b: Field) -> Field {
    a * b
}

#[test]
fn nullifier_kat_test() {
    let inputs = OprfQueryInputs::<30, 7> {
        user_pk: [
            PublicKey {
                x: 19037598474602150174935475944965340829216795940473064039209388058233204431288,
                y: 3549932221586364715003722955756497910920276078443163728621283280434115857197,
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
            4627252264155703937895399512035115439496525887928100557956386779559557258079,
            20625487727076366435094930488407344755788922107125249486987640506581708310418,
        ],
        query_s: 397081558475992644851544094048753020217124815738999382096255860760106483760,
        merkle_proof: MerkleProof::<30> {
            mt_index: 1,
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
        beta: 2387462819376525223098422965806766751285565755980265072594901385662518965922,
    };
    let nullifer_inputs = OprfNullifierInputs::<30, 7> {
        query_inputs: inputs,
        issuer_schema_id: 1,
        cred_hashes: super::types::CredentialHashes {
            claims_hash: 14272087287699568472569351444185311392108883722570788958733484799744115401870,
            associated_data_hash: 0,
        },
        cred_genesis_issued_at: 1767868120,
        cred_expires_at: 1767868180,
        cred_s: 1785197794318390548654263507521729446174585997835004080357493002880021427752,
        cred_r: [
            9716162517813998269973089361571651784159199085806289463178774674474552458864,
            6858161934880479087336794169055762635352680692798466775715085760374212641424,
        ],
        cred_id: 12176925761186149284,
        cred_user_id_r: 19016519542686775328775746932795543103858066763212549618980890183285781521458,
        dlog_e: 5609293693019386176508931649877337091590878173635241438306548223920379307458,
        dlog_s: 1167493435914595771361530871033173621661932035514996719837354510862251986174,
        id_commitment_r: 13858286952051413225628647635562976319232237623524873683310157982584937807428,
        oprf_response: BabyJubJubPoint::new(
            11771927497930831763844779626723106344742708040976110136703486119568919340013,
            19299702061490581533153169629464406607119112637706400365988657399831357218309,
        ),
        oprf_response_blinded: BabyJubJubPoint::new(
            6882462243439192795495492197995100450516328082301652413647059141168822449465,
            11410248488379662098266045802345135482683496756414401793793460258484335221028,
        ),
    };
    let rp_id: Field = 950325648507560155068233096743093215539447660945;
    let action: Field = 84721944028150696728472418813119358007006361082259892623669024918011698311;
    let nonce: Field = 3828243042530729863575259406060047358359204915498281882023481753463151732796;
    let signal_hash: Field =
        37938388892362834151584770384290207919364301626797345218722464515205243407;
    let root: Field = 4959814736111706042728533661656003495359474679272202023690954858781105690707;
    let depth = 30;
    let cred_pk = PublicKey {
        x: 21825204959029483311433036009853709113262520481918849765727459753607131160346,
        y: 8339486770249821464793634710648189540136988043780169655155172519121840615364,
    };
    let oprf_pk = PublicKey {
        x: 16048296497646113681290127133582586009660277510307938775951186660467382774945,
        y: 13451097916688865791218925679662796109386737920791997438101375513111619197164,
    };
    let current_timestamp = 1767868101;
    let cred_genesis_issued_at_min = 0;

    let expected_id_comm =
        4802796577484149062247786624766778023092411368115151701918465360876116430391;
    let expected_nullifier =
        21342856517406476000190785734870568200315738457615815351702849709270076362125;

    let outputs = oprf_nullifier(
        cred_pk,
        current_timestamp,
        cred_genesis_issued_at_min,
        root,
        depth,
        rp_id,
        action,
        oprf_pk,
        signal_hash,
        nonce,
        nullifer_inputs,
    );

    assert(outputs.id_commitment == expected_id_comm, "ID Commitment mismatch");
    assert(outputs.nullifier == expected_nullifier, "Nullifier mismatch");
}
