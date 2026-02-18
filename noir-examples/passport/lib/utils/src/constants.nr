pub global YYYYMMDD_DATE_LENGTH: u32 = 8;
pub global YYMMDD_DATE_LENGTH: u32 = 6;

// Index for the country of issuance of the passport
pub global PASSPORT_MRZ_ISSUING_COUNTRY_INDEX: u32 = 2;
// Length of the country code in the MRZ
pub global PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH: u32 = 3;
// Index for the three letter code of the country of citizenship
// Note that the first three letter code (index 2) in the MRZ is the country of issuance
// not citizenship. It is important to keep in mind for residence permits
// where the issuing country differs from the citizenship country
pub global PASSPORT_MRZ_NATIONALITY_INDEX: u32 = 54;
// Length of the country code in the MRZ
pub global PASSPORT_MRZ_NATIONALITY_LENGTH: u32 = 3;
// Index for the gender of the passport holder (M, F or < if unspecified)
pub global PASSPORT_MRZ_GENDER_INDEX: u32 = 64;
// Index for the date of expiry (YYMMDD)
pub global PASSPORT_MRZ_EXPIRY_DATE_INDEX: u32 = 65;
// Index for the date of birth (YYMMDD) in TD1 (i.e. passport) MRZ
pub global PASSPORT_MRZ_BIRTHDATE_INDEX: u32 = 57;
// Length of the date of birth in the MRZ
pub global PASSPORT_MRZ_BIRTHDATE_LENGTH: u32 = YYMMDD_DATE_LENGTH;
// Length of the year of birth in the MRZ
pub global PASSPORT_MRZ_YEAR_OF_BIRTH_LENGTH: u32 = 2;
// Index for the document number in the MRZ
pub global PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX: u32 = 44;
// Length of the document number in the MRZ
pub global PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH: u32 = 9;
// Index for the document type in the MRZ
pub global PASSPORT_MRZ_DOCUMENT_TYPE_INDEX: u32 = 0;
// Index for the name of the passport holder
pub global PASSPORT_MRZ_NAME_INDEX: u32 = 5;
// Length of the name of the passport holder
pub global PASSPORT_MRZ_NAME_LENGTH: u32 = 39;
// Length of the MRZ on a passport
pub global PASSPORT_MRZ_LENGTH: u32 = 88;
// Length of the DG1 on a passport
pub global PASSPORT_DG1_LENGTH: u32 = 93;

// Index for the country of issuance of the ID card
pub global ID_CARD_MRZ_ISSUING_COUNTRY_INDEX: u32 = 2;
// Length of the country code in the MRZ
pub global ID_CARD_MRZ_ISSUING_COUNTRY_LENGTH: u32 = 3;
// Note that the first three letter code (index 2) in the MRZ is the country of issuance
// not citizenship. It is important to keep in mind for residence permits
// where the issuing country differs from the citizenship country
pub global ID_CARD_MRZ_NATIONALITY_INDEX: u32 = 45;
// Length of the country code in the MRZ
pub global ID_CARD_MRZ_NATIONALITY_LENGTH: u32 = 3;
// Index for the gender of the passport holder (M, F or < if unspecified)
pub global ID_CARD_MRZ_GENDER_INDEX: u32 = 37;
// Index for the date of expiry (YYMMDD)
pub global ID_CARD_MRZ_EXPIRY_DATE_INDEX: u32 = 38;
// Index for the date of birth (YYMMDD) in TD3 (i.e. ID cards) MRZ
pub global ID_CARD_MRZ_BIRTHDATE_INDEX: u32 = 30;
// Length of the date of birth in the MRZ
pub global ID_CARD_MRZ_BIRTHDATE_LENGTH: u32 = YYMMDD_DATE_LENGTH;
// Length of the year of birth in the MRZ
pub global ID_CARD_MRZ_YEAR_OF_BIRTH_LENGTH: u32 = 2;
// Index for the document number in the MRZ
pub global ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX: u32 = 5;
// Length of the document number in the MRZ
pub global ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH: u32 = 9;
// Index for the document type in the MRZ
pub global ID_CARD_MRZ_DOCUMENT_TYPE_INDEX: u32 = 0;
// Index for the name of the passport holder
pub global ID_CARD_MRZ_NAME_INDEX: u32 = 60;
/// Length for the MRZ on an ID card
pub global ID_CARD_MRZ_NAME_LENGTH: u32 = 30;
// Length of the MRZ on an ID card
pub global ID_CARD_MRZ_LENGTH: u32 = 90;
// Length of the DG1 on an ID card
pub global ID_CARD_DG1_LENGTH: u32 = 95;

// ASCII_CODE FOR <
pub global ASCII_CODE_FOR_LESS_THAN: u8 = 60;

/// Offset of the MRZ in the DG1
pub global DG1_TO_MRZ_OFFSET: u32 = 5;

// ECDSA curves mapping
pub global ECDSA_CURVE_P256: u32 = 0;
pub global ECDSA_CURVE_P384: u32 = 1;
pub global ECDSA_CURVE_P521: u32 = 2;
pub global ECDSA_CURVE_BRAINPOOL_B256R1: u32 = 3;
pub global ECDSA_CURVE_BRAINPOOL_B256T1: u32 = 4;
pub global ECDSA_CURVE_BRAINPOOL_B384R1: u32 = 5;
pub global ECDSA_CURVE_BRAINPOOL_B384T1: u32 = 6;
pub global ECDSA_CURVE_BRAINPOOL_B512R1: u32 = 7;
pub global ECDSA_CURVE_BRAINPOOL_B512T1: u32 = 8;

// Proof type to identify the circuit used for a given parameter commitment
pub global PROOF_TYPE_DISCLOSE: u8 = 0;
pub global PROOF_TYPE_AGE: u8 = 1;
pub global PROOF_TYPE_BIRTHDATE: u8 = 2;
pub global PROOF_TYPE_EXPIRY_DATE: u8 = 3;
pub global PROOF_TYPE_NATIONALITY_INCLUSION: u8 = 4;
pub global PROOF_TYPE_NATIONALITY_EXCLUSION: u8 = 5;
pub global PROOF_TYPE_ISSUING_COUNTRY_INCLUSION: u8 = 6;
pub global PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION: u8 = 7;
pub global PROOF_TYPE_BIND: u8 = 8;
pub global PROOF_TYPE_SANCTIONS_EXCLUSION: u8 = 9;
pub global PROOF_TYPE_FACEMATCH: u8 = 10;

// DG1 length
pub global DG1_LENGTH: u32 = 95;
// EContent length
pub global ECONTENT_LENGTH: u32 = 700;
// Signed attributes length
pub global SIGNED_ATTRS_LENGTH: u32 = 220;
// MAX MRZ length = ID card MRZ length
pub global MAX_MRZ_LENGTH: u32 = ID_CARD_MRZ_LENGTH;

// SHA1 digest length
pub global SHA1_DIGEST_LENGTH: u32 = 20;
// SHA224 digest length
pub global SHA224_DIGEST_LENGTH: u32 = 28;
// SHA256 digest length
pub global SHA256_DIGEST_LENGTH: u32 = 32;
// SHA384 digest length
pub global SHA384_DIGEST_LENGTH: u32 = 48;
// SHA512 digest length
pub global SHA512_DIGEST_LENGTH: u32 = 64;

pub global SHA1_IDENTIFIER: u32 = 1;
pub global SHA224_IDENTIFIER: u32 = 2;
pub global SHA256_IDENTIFIER: u32 = 3;
pub global SHA384_IDENTIFIER: u32 = 4;
pub global SHA512_IDENTIFIER: u32 = 5;

pub global DG2_MAX_HASH_SIZE: u32 = SHA512_DIGEST_LENGTH;

pub global EMPTY_ALPHA3_COUNTRY_CODE: str<3> = "\0\0\0";

// The different nullifier types

// Nullifier purely derived from the private nullifier and the scopes
// with no secret
pub global NON_SALTED_NULLIFIER: Field = 0;
// Nullifier derived from the private nullifier and the scopes with a secret
pub global SALTED_NULLIFIER: Field = 1;
// Nullifier purely derived from the private nullifier and the scopes with no secret
// Used for mock proofs (i.e. ZKR)
pub global NON_SALTED_MOCK_NULLIFIER: Field = 2;
// Nullifier derived from the private nullifier and the scopes with a secret
// Used for mock proofs (i.e. ZKR)
pub global SALTED_MOCK_NULLIFIER: Field = 3;

// P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<
pub global SAMPLE_DG1: [u8; DG1_LENGTH] = [
    0x61, 0x5B, 0x5F, 0x1F, 0x58, 80, 60, 65, 85, 83, 83, 73, 76, 86, 69, 82, 72, 65, 78, 68, 60,
    60, 74, 79, 72, 78, 78, 89, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
    60, 60, 60, 60, 80, 65, 49, 50, 51, 52, 53, 54, 55, 95, 65, 85, 83, 56, 56, 49, 49, 49, 50, 95,
    77, 51, 48, 48, 49, 48, 49, 95, 60, 67, 89, 66, 69, 82, 67, 73, 84, 89, 60, 60, 60, 60, 60, 60,
    0, 0,
];

// I<ZKRZID222222<<<<<<<<<<<<<<<<9801157F3001018ZKR<<<<<<<<<<<2DOE<<JANE<<<<<<<<<<<<<<<<<<<<<
pub global ID_CARD_SAMPLE_DG1: [u8; DG1_LENGTH] = [
    0x61, 0x5B, 0x5F, 0x1F, 0x58, 73, 60, 90, 75, 82, 90, 73, 68, 50, 50, 50, 50, 50, 50, 60, 60,
    60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 57, 56, 48, 49, 49, 53, 55, 70, 51, 48,
    48, 49, 48, 49, 56, 90, 75, 82, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 50, 68, 79, 69, 60,
    60, 74, 65, 78, 69, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
    60, 60,
];

// ID card with an extended document number (here a Portuguese National ID specimen)
// I<PRT007666667<ZZ00<<<<<<<<<<<8303143M3405293PRT<<<<<<<<<<<4CACADOR<DE<ARAUJO<<ANDRE<ESTEV
pub global EXTENDED_ID_CARD_SAMPLE_DG1: [u8; DG1_LENGTH] = [
    0x61, 0x5B, 0x5F, 0x1F, 0x58, 73, 60, 80, 82, 84, 48, 48, 55, 54, 54, 54, 54, 54, 55, 60, 90,
    90, 48, 48, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 56, 51, 48, 51, 49, 52, 51, 77, 51, 52,
    48, 53, 50, 57, 51, 80, 82, 84, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 52, 67, 65, 67, 65,
    68, 79, 82, 60, 68, 69, 60, 65, 82, 65, 85, 74, 79, 60, 60, 65, 78, 68, 82, 69, 60, 69, 83, 84,
    69, 86,
];
