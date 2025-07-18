use ryan_sha256_compression::ryan_sha256_digest_block_u32;
use ryan_sha256_constants::{MAX_MSG_LEN, RANDOM_BYTES_MANY_ROUNDS};
use std::hash::sha256_compression;

pub mod ryan_sha256_noir;
pub(crate) mod ryan_sha256_compression;
pub(crate) mod ryan_sha256_constants;

fn is_id_card(dg1: [u8; 95]) -> bool {
    // For passport, the last two bytes are 0
    // since the real length is 93 for passports
    // while it is 95 for ID cards
    (dg1[93] != 0) & (dg1[94] != 0)
}

#[test]
fn test_failing_sha256_var() {
    let dg1: [u8; 95] = [
        42, 19, 88, 237, 91, 63, 129, 7, 250, 198, 14, 76, 211, 45, 5, 99, 170, 38, 240, 201, 64,
        123, 3, 81, 33, 156, 212, 18, 199, 111, 222, 61, 143, 247, 8, 195, 29, 157, 132, 71, 102,
        17, 173, 108, 245, 214, 224, 66, 115, 86, 189, 234, 90, 44, 207, 16, 58, 134, 103, 251, 193,
        35, 140, 248, 79, 105, 202, 137, 100, 196, 125, 31, 83, 41, 209, 93, 10, 229, 144, 116, 225,
        67, 133, 204, 77, 112, 69, 253, 154, 246, 17, 99, 88, 0, 0,
    ];

    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;
    let mut x: u64 = 0;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        println("this is reached");
        x = 3;
        dg1_size = 95;
    }

    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    // let other_hash = sha256::sha256_var(dg1, dg1_size);
    let dg1_hash_attempt_1 = ryan_sha256_noir::sha256_var(dg1, x + 95 - x); // So this gives the correct result but falsely fails R1CS constraints
    let dg1_hash_attempt_2 = ryan_sha256_noir::sha256_var(dg1, dg1.len() as u64); // This gives the wrong result but succeeds in R1CS constraints
    let other_dg1_hash = sha256::digest(dg1);
    println("This is Noir's dg1_hash");
    println(other_dg1_hash);

    // println(other_hash);
    println("This is the dg1_hash_attempt_1");
    println(dg1_hash_attempt_1);

    println("This is the dg1_hash_attempt_2");
    println(dg1_hash_attempt_2);
}

#[test]
fn test_sha256_var() {
    // --- Let's test two versions of `sha256_var` against each other ---
    for idx in 0..10 {
        let thing_to_absorb: [u8; MAX_MSG_LEN] = RANDOM_BYTES_MANY_ROUNDS[idx];

        let mut msg_len = MAX_MSG_LEN;
        if thing_to_absorb[0] == 0 {
            msg_len -= 2;
        }

        let blackbox_result = sha256::sha256_var(thing_to_absorb, msg_len as u64);
        let ryan_result = ryan_sha256_noir::sha256_var(thing_to_absorb, msg_len as u64);

        println(blackbox_result);
        println(ryan_result);
        assert_eq(blackbox_result, ryan_result);
    }
}

#[test]
fn test_ryan_sha256_digest_block_u32() {
    let random_states: [[u32; 8]; 10] = [
        [
            3711890665, 3714332401, 3387837403, 1311576937, 2850423420, 1766807436, 279261662,
            980698040,
        ],
        [
            241080654, 2776327254, 2836034795, 4011727061, 692717810, 3472968387, 2336079546,
            3472865588,
        ],
        [
            1814694129, 898153453, 2718683824, 1980947199, 124660220, 3730354208, 3567088773,
            1301108289,
        ],
        [
            3070321822, 3745622196, 1475927390, 1408189715, 157514634, 200331949, 2985323570,
            1134610593,
        ],
        [
            3776767489, 3958445956, 34729136, 2244258599, 935645256, 1185556939, 1882358357,
            1071787888,
        ],
        [
            1428952096, 3457008629, 4079094404, 2092226862, 395173293, 3283923843, 865111316,
            2696302365,
        ],
        [
            3193282606, 2455080160, 1470231557, 52232517, 3123999614, 1751048468, 1511590211,
            3572795290,
        ],
        [
            2482781779, 2543833787, 1648932745, 1094288520, 1490389861, 1062138401, 2701750777,
            4086905298,
        ],
        [
            2073696290, 429529299, 658199888, 1237181425, 3259720900, 1132273219, 820741923,
            3134182660,
        ],
        [
            2106415170, 4057092793, 1060978477, 3378096126, 2758276607, 938643281, 2868160936,
            472120090,
        ],
    ];
    let random_things_to_absorb: [[u32; 16]; 10] = [
        [
            1277355385, 22445438, 817981005, 1510743426, 2669419464, 243984557, 3715704331,
            3351129034, 1050294448, 1326592289, 130423761, 2623807512, 1561557411, 2521042731,
            1097327247, 3068172910,
        ],
        [
            642031562, 2531093294, 209598467, 1636419963, 1035403787, 49355406, 1571735684,
            3160016159, 4232504228, 557530806, 2447633372, 2637401205, 363737925, 3293614601,
            236471905, 3997477011,
        ],
        [
            572654401, 3902053496, 3408636837, 3607322483, 2470026909, 2752661972, 499944812,
            2880063031, 2441148372, 600390524, 4020459520, 2921542983, 2499385623, 2371016017,
            3829979851, 3342537836,
        ],
        [
            3008025510, 917961269, 2923099632, 7696709, 2135557940, 3460350958, 2966732963,
            1625920042, 2673707951, 3696379411, 1480305399, 3784819888, 2398046752, 1157717730,
            2858103740, 3269707097,
        ],
        [
            2288317606, 2595904485, 42896947, 1637923610, 908051416, 2463899481, 3311817896,
            141630765, 2801911017, 251176618, 4096056149, 555154172, 3150320497, 3036229357,
            1132287542, 3859394292,
        ],
        [
            1282404551, 72031527, 1643203889, 1560283573, 4104931948, 1517886706, 3446512707,
            3312007269, 3042382991, 3867167222, 1613960926, 3449768118, 4042603251, 4151709098,
            3975368320, 2602443230,
        ],
        [
            293867709, 896730560, 4058455315, 296253730, 2506231107, 4007085280, 907876420,
            3425083873, 1737118966, 536585638, 472348727, 2373166844, 2143603884, 2847565666,
            1405187978, 270342293,
        ],
        [
            3822838650, 3968797499, 2404366212, 1908633276, 2478306128, 2834276327, 2519762659,
            3753423485, 2690247494, 932818742, 2651610469, 3552893028, 253034649, 813152430,
            3816068176, 3762292230,
        ],
        [
            898570312, 673147241, 520504408, 3808700629, 2797906140, 1823662319, 548008261,
            340382032, 3564205661, 292516889, 1563614420, 2249064997, 177816195, 3597367921,
            3022258837, 1621940911,
        ],
        [
            707284061, 2231665729, 2478251141, 2894474131, 3916603775, 4213252696, 1395674200,
            350417223, 2277379131, 2533289716, 1350595999, 4067840646, 895320447, 3184565247,
            468404587, 3529508635,
        ],
    ];

    // --- Let's test the two versions of `sha256_compression` against each other! ---
    for idx in 0..10 {
        let thing_to_absorb: [u32; 16] = random_things_to_absorb[idx];
        let state: [u32; 8] = random_states[idx];
        let blackbox_result = sha256_compression(thing_to_absorb, state);
        let ryan_result = ryan_sha256_digest_block_u32(state, thing_to_absorb);

        println(blackbox_result);
        println(ryan_result);
        assert_eq(blackbox_result, ryan_result);
    }
}
