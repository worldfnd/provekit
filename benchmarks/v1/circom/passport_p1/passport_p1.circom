pragma circom 2.1.9;

// This circuit deliberately imports the pinned Self primitives rather than
// duplicating their RSA, SHA-256, or DSC registry-leaf implementations.
include "../../../../target/v1-benchmarks/sources/self/circuits/circuits/utils/passport/customHashers.circom";
include "../../../../target/v1-benchmarks/sources/self/circuits/circuits/utils/passport/signatureAlgorithm.circom";
include "../../../../target/v1-benchmarks/sources/self/circuits/circuits/utils/passport/date/isValid.circom";
include "../../../../target/v1-benchmarks/sources/self/circuits/circuits/utils/passport/date/isOlderThan.circom";
include "../../../../target/v1-benchmarks/sources/self/circuits/circuits/utils/passport/passportVerifier.circom";
include "../../../../target/v1-benchmarks/sources/self/circuits/circuits/utils/passport/constants.circom";
include "../../../../target/v1-benchmarks/sources/self/circuits/circuits/utils/passport/checkPubkeysEqual.circom";
include "../../../../target/v1-benchmarks/sources/self/circuits/circuits/utils/passport/checkPubkeyPosition.circom";
include "../../../../target/v1-benchmarks/sources/self/circuits/circuits/utils/crypto/bitify/bytes.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";

/// Restricts a public current-date digit to its decimal representation.
template DecimalDigit() {
    signal input value;

    component inRange = LessThan(4);
    inRange.in[0] <== value;
    inRange.in[1] <== 10;
    inRange.out === 1;
}

/// P1's monolithic passport statement.
///
/// It preserves Self's SHA-256 DG1/eContent/signed-attributes chain,
/// RSA-65537-4096 signature verification, and DSC registry-leaf construction.
/// It intentionally excludes Self registration's commitment/nullifier and every
/// disclosure, OFAC, scope, and CSCA certificate-signature operation.
template PassportP1() {
    var DG1_LEN = 93;
    var MAX_DSC_LENGTH = getMaxDSCLength();
    var DSC_TREE_LEVELS = getMaxDSCLevels();
    var SIGNATURE_ALGORITHM = 10; // rsa_sha256_65537_4096
    var RSA_CHUNK_BITS = 120;
    var RSA_CHUNKS = 35;
    var RSA_CHUNKS_SCALED = 35;
    var MAX_ECONTENT_PADDED_LEN = 512;
    var MAX_SIGNED_ATTR_PADDED_LEN = 256;
    var DSC_PUBKEY_PREFIX_LEN = 33;
    var DSC_PUBKEY_SUFFIX_LEN = 0;
    var MAX_DSC_PUBKEY_LENGTH = 525;

    assert(MAX_DSC_LENGTH % 64 == 0);

    signal input raw_dsc[MAX_DSC_LENGTH];
    signal input raw_dsc_actual_length;
    signal input dsc_pubKey_offset;
    signal input dsc_pubKey_actual_size;

    signal input dg1[DG1_LEN];
    signal input dg1_hash_offset;
    signal input eContent[MAX_ECONTENT_PADDED_LEN];
    signal input eContent_padded_length;
    signal input signed_attr[MAX_SIGNED_ATTR_PADDED_LEN];
    signal input signed_attr_padded_length;
    signal input signed_attr_econtent_hash_offset;
    signal input pubKey_dsc[RSA_CHUNKS_SCALED];
    signal input signature_passport[RSA_CHUNKS_SCALED];

    // These are the P1 statement's common public values.  They are not
    // fixture-specific constants: registry membership and date/age checks bind
    // them to the private passport witness.
    signal input merkle_root;
    signal input leaf_depth;
    signal input path[DSC_TREE_LEVELS];
    signal input siblings[DSC_TREE_LEVELS];
    signal input csca_tree_leaf;
    signal input current_date[6];
    signal input minimum_age[2];

    AssertBytes(MAX_DSC_LENGTH)(raw_dsc);

    component dscPubkeyOffsetBits = Num2Bits(12);
    dscPubkeyOffsetBits.in <== dsc_pubKey_offset;
    component dscPubkeySizeBits = Num2Bits(12);
    dscPubkeySizeBits.in <== dsc_pubKey_actual_size;
    component dscPubkeyEndBits = Num2Bits(12);
    dscPubkeyEndBits.in <== dsc_pubKey_offset + dsc_pubKey_actual_size;
    component rawDscLengthBits = Num2Bits(12);
    rawDscLengthBits.in <== raw_dsc_actual_length;

    signal dscPubkeyInRange <== LessEqThan(12)([
        dsc_pubKey_offset + dsc_pubKey_actual_size,
        raw_dsc_actual_length
    ]);
    dscPubkeyInRange === 1;

    // This is exactly Self's production DSC registry-leaf construction.
    signal dsc_hash <== PackBytesAndPoseidon(MAX_DSC_LENGTH)(raw_dsc);
    signal dsc_hash_with_actual_length <== Poseidon(2)([dsc_hash, raw_dsc_actual_length]);
    signal dsc_tree_leaf <== Poseidon(2)([dsc_hash_with_actual_length, csca_tree_leaf]);
    signal computed_merkle_root <== BinaryMerkleRoot(DSC_TREE_LEVELS)(
        dsc_tree_leaf,
        leaf_depth,
        path,
        siblings
    );
    merkle_root === computed_merkle_root;

    signal dsc_pubKey_prefix_start_index <== dsc_pubKey_offset - DSC_PUBKEY_PREFIX_LEN;
    signal dsc_pubKey_net_length <== DSC_PUBKEY_PREFIX_LEN + dsc_pubKey_actual_size + DSC_PUBKEY_SUFFIX_LEN;
    component dscPubkeyPrefixBits = Num2Bits(log2Ceil(MAX_DSC_LENGTH));
    dscPubkeyPrefixBits.in <== dsc_pubKey_prefix_start_index;
    component dscPubkeyNetLengthBits = Num2Bits(log2Ceil(MAX_DSC_LENGTH));
    dscPubkeyNetLengthBits.in <== dsc_pubKey_net_length;
    component dscPubkeyEndLengthBits = Num2Bits(log2Ceil(MAX_DSC_LENGTH));
    dscPubkeyEndLengthBits.in <== dsc_pubKey_prefix_start_index + dsc_pubKey_net_length;
    signal dscPubkeyEndInRange <== LessEqThan(log2Ceil(MAX_DSC_LENGTH))([
        dsc_pubKey_prefix_start_index + dsc_pubKey_net_length,
        raw_dsc_actual_length
    ]);
    dscPubkeyEndInRange === 1;

    signal pubkey_with_prefix_and_suffix[
        DSC_PUBKEY_PREFIX_LEN + MAX_DSC_PUBKEY_LENGTH + DSC_PUBKEY_SUFFIX_LEN
    ] <== SelectSubArray(
        MAX_DSC_LENGTH,
        DSC_PUBKEY_PREFIX_LEN + MAX_DSC_PUBKEY_LENGTH + DSC_PUBKEY_SUFFIX_LEN
    )(
        raw_dsc,
        dsc_pubKey_prefix_start_index,
        dsc_pubKey_net_length
    );
    CheckPubkeyPosition(
        DSC_PUBKEY_PREFIX_LEN,
        MAX_DSC_PUBKEY_LENGTH,
        DSC_PUBKEY_SUFFIX_LEN,
        SIGNATURE_ALGORITHM
    )(
        pubkey_with_prefix_and_suffix,
        dsc_pubKey_actual_size
    );

    signal extracted_dsc_pubKey[MAX_DSC_PUBKEY_LENGTH];
    for (var i = 0; i < MAX_DSC_PUBKEY_LENGTH; i++) {
        extracted_dsc_pubKey[i] <== pubkey_with_prefix_and_suffix[DSC_PUBKEY_PREFIX_LEN + i];
    }
    CheckPubkeysEqual(
        RSA_CHUNK_BITS,
        RSA_CHUNKS_SCALED,
        1,
        MAX_DSC_PUBKEY_LENGTH
    )(
        pubKey_dsc,
        extracted_dsc_pubKey,
        dsc_pubKey_actual_size
    );

    component passportVerifier = PassportVerifier(
        DG1_LEN,
        256,
        256,
        SIGNATURE_ALGORITHM,
        RSA_CHUNK_BITS,
        RSA_CHUNKS,
        MAX_ECONTENT_PADDED_LEN,
        MAX_SIGNED_ATTR_PADDED_LEN
    );
    passportVerifier.dg1 <== dg1;
    passportVerifier.dg1_hash_offset <== dg1_hash_offset;
    passportVerifier.eContent <== eContent;
    passportVerifier.eContent_padded_length <== eContent_padded_length;
    passportVerifier.signed_attr <== signed_attr;
    passportVerifier.signed_attr_padded_length <== signed_attr_padded_length;
    passportVerifier.signed_attr_econtent_hash_offset <== signed_attr_econtent_hash_offset;
    passportVerifier.pubKey_dsc <== pubKey_dsc;
    passportVerifier.signature_passport <== signature_passport;

    // Self's passport layout stores YYMMDD DOB at 62 and expiry at 70.
    signal birth_date_ascii[6];
    signal expiry_date_ascii[6];
    for (var i = 0; i < 6; i++) {
        birth_date_ascii[i] <== dg1[62 + i];
        expiry_date_ascii[i] <== dg1[70 + i];
        DecimalDigit()(current_date[i]);
    }

    IsValid()(current_date, expiry_date_ascii);
    component age = IsOlderThan();
    age.majorityASCII <== minimum_age;
    age.currDate <== current_date;
    age.birthDateASCII <== birth_date_ascii;
    age.out === 1;

    // A common, integrity-bound fixture identifier.  It is an output (and
    // therefore public), derived from the same private DG1 bytes hashed above.
    signal output fixture_id <== PackBytesAndPoseidon(DG1_LEN)(dg1);
}

component main { public [merkle_root, current_date, minimum_age] } = PassportP1();
