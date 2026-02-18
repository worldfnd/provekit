use crate::{
    check_zero_padding, find_subarray_index, get_mrz_from_dg1, get_name_from_mrz,
    pack_be_bytes_into_fields, pack_be_bytes_into_u128s, split_array,
    unsafe_get_asn1_element_length,
};

use super::constants::{
    DG1_TO_MRZ_OFFSET, ID_CARD_MRZ_BIRTHDATE_INDEX, ID_CARD_MRZ_BIRTHDATE_LENGTH,
    ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX, ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH,
    ID_CARD_MRZ_ISSUING_COUNTRY_INDEX, ID_CARD_MRZ_NAME_INDEX, ID_CARD_MRZ_NAME_LENGTH,
    ID_CARD_MRZ_NATIONALITY_INDEX, PASSPORT_MRZ_BIRTHDATE_INDEX, PASSPORT_MRZ_BIRTHDATE_LENGTH,
    PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX, PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH,
    PASSPORT_MRZ_ISSUING_COUNTRY_INDEX, PASSPORT_MRZ_NAME_INDEX, PASSPORT_MRZ_NAME_LENGTH,
    PASSPORT_MRZ_NATIONALITY_INDEX,
};
use super::constants::EXTENDED_ID_CARD_SAMPLE_DG1;
use super::constants::ID_CARD_SAMPLE_DG1;
use super::constants::SAMPLE_DG1;
use super::get_dob_from_mrz;
use super::get_document_number_from_mrz;
use super::{
    get_expiry_date_from_mrz, get_issuing_country_from_mrz, get_nationality_from_mrz,
    pack_be_bit_into_field,
};
use super::get_yob_from_mrz;
use super::types::{
    DG1Data, MRZData, MRZDOB, MRZDocumentNumber, MRZIssuingCountry, MRZName, MRZNameIdCard,
    MRZNationality, SaltedValue,
};

// Testing utilities

/// DG1 Builder
/// Usage:
/// ```nr
/// let dg1 = DG1Builder::new([0; 95])
/// .with_document_number([68, 60, 60, etc...])
/// .with_name([68, 60, 60])
/// .with_dob([68, 60, 60])
/// .build();
pub struct DG1Builder {
    dg1: DG1Data,
}

impl DG1Builder {
    pub fn new(dg1: DG1Data) -> Self {
        Self { dg1 }
    }

    pub fn build(mut self: Self) -> DG1Data {
        self.dg1
    }

    pub fn build_mrz(mut self: Self) -> MRZData {
        get_mrz_from_dg1(self.dg1)
    }

    pub fn set_is_id_card(mut self: Self) -> Self {
        // Set the last two bytes to NON 0 to indicate an ID card
        self.dg1[93] = 1;
        self.dg1[94] = 1;
        self
    }

    pub fn with_nationality(mut self: Self, country_code: MRZNationality) -> Self {
        for i in 0..3 {
            // + 5 as it goes through an mrz decoding
            self.dg1[PASSPORT_MRZ_NATIONALITY_INDEX + i + DG1_TO_MRZ_OFFSET] = country_code[i];
            self.dg1[PASSPORT_MRZ_ISSUING_COUNTRY_INDEX + i + DG1_TO_MRZ_OFFSET] = country_code[i];
        }
        self
    }

    pub fn with_nationality_id_card(mut self: Self, country_code: MRZNationality) -> Self {
        for i in 0..3 {
            self.dg1[ID_CARD_MRZ_NATIONALITY_INDEX + i + DG1_TO_MRZ_OFFSET] = country_code[i];
        }
        self
    }

    pub fn with_issuing_country(mut self: Self, country_code: MRZIssuingCountry) -> Self {
        for i in 0..3 {
            self.dg1[PASSPORT_MRZ_ISSUING_COUNTRY_INDEX + i + DG1_TO_MRZ_OFFSET] = country_code[i];
        }
        self
    }

    pub fn with_issuing_country_id_card(mut self: Self, country_code: MRZIssuingCountry) -> Self {
        for i in 0..3 {
            self.dg1[ID_CARD_MRZ_ISSUING_COUNTRY_INDEX + i + DG1_TO_MRZ_OFFSET] = country_code[i];
        }
        self
    }

    pub fn with_document_number(mut self: Self, document_number: MRZDocumentNumber) -> Self {
        for i in 0..PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH {
            self.dg1[PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX + i + 5] = document_number[i];
        }
        self
    }

    pub fn with_document_number_id_card(
        mut self: Self,
        document_number: MRZDocumentNumber,
    ) -> Self {
        for i in 0..ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH {
            self.dg1[ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX + i + DG1_TO_MRZ_OFFSET] =
                document_number[i];
        }
        self
    }

    pub fn with_name(mut self: Self, name: MRZName) -> Self {
        for i in 0..PASSPORT_MRZ_NAME_LENGTH {
            self.dg1[PASSPORT_MRZ_NAME_INDEX + i + DG1_TO_MRZ_OFFSET] = name[i];
        }
        self
    }

    pub fn with_name_id_card(mut self: Self, name: MRZNameIdCard) -> Self {
        for i in 0..ID_CARD_MRZ_NAME_LENGTH {
            self.dg1[ID_CARD_MRZ_NAME_INDEX + i + DG1_TO_MRZ_OFFSET] = name[i];
        }
        self
    }

    pub fn with_dob(mut self: Self, dob: MRZDOB) -> Self {
        for i in 0..PASSPORT_MRZ_BIRTHDATE_LENGTH {
            self.dg1[PASSPORT_MRZ_BIRTHDATE_INDEX + i + DG1_TO_MRZ_OFFSET] = dob[i];
        }
        self
    }

    pub fn with_dob_id_card(mut self: Self, dob: MRZDOB) -> Self {
        for i in 0..ID_CARD_MRZ_BIRTHDATE_LENGTH {
            self.dg1[ID_CARD_MRZ_BIRTHDATE_INDEX + i + DG1_TO_MRZ_OFFSET] = dob[i];
        }
        self
    }
}

/// Packing bytes functions

#[test]
fn test_pack_be_bytes_into_u128() {
    let packed1 = pack_be_bytes_into_u128s::<512, _, 15>(TEST_BYTES);
    assert(
        packed1
            == [
                0xa906a6bf52c2d3b6dcc3e53e8df2c2,
                0xa0a652bc1a96ef6fa85aaaac8a2793,
                0xd2aa634a40e786072d1a84a726ee35,
                0x20deee9d92dd32e9d1661cad3fd748,
                0x59c58bff771bcb1007ab5292034b01,
                0xb105cd7c3f8bdffffa8976a1d6712b,
                0x7f04e817f0861ba18ffdc4e9656bd2,
                0xca6ad55f4dc9e1437ae528bff4440b,
                0x0cdf23c048109f118dbc4f062526ec,
                0xc57749fc145d2a6f68c95a0bf1345a,
                0x1744b7ad88a820d428b0f1c79a6660,
                0x21a17ae68fddadbb6d54c97ecbe1e3,
                0x3596b41957a1a78af81fbe9f418d92,
                0x5398a2f749a773190f5d838013b898,
                0xef83111bf9b7819fd12b33ff682590,
                0x56989a6176dfd100ae89dd7936e9f0,
                0x4f3d7ab2e41ba2cb404c3d6cef8740,
                0xc81a370e672704f5f31450f9156d93,
                0x2c9ad440424450b81c303c51d405d3,
                0x5d3aaebc67b2ba64a2f9546349fb9e,
                0xdced3dbea6d67fe49c3f31562ffba7,
                0xa67a19f7fcecb81235e7706b20ecc4,
                0x2fb5c8f5d8ddac8df1c6917eb31bad,
                0xd9478e0dcd3f2ab125ccc6a68c4447,
                0x2ef19aff06bf67ab4226a331ffa737,
                0x5e9ea156076a09e78b919d8c5dee0f,
                0x0b427e9391893f58968fc2d96a2775,
                0x432d27b533c103f1509b4f4fc43ac7,
                0xe0e6d9598280b0aa0f2902b0aa3b3a,
                0xa04da3f98c5cfe8d4d8f9e1fb4e89c,
                0x7e463b5ebaf81c1485efeb44e634f9,
                0xae87ec4262fcfd075f5554475547a3,
                0xfb2297b7ffc0deeb3a1b27effc6b6c,
                0xd3b801cbc8e237620d8dd9adc29551,
                0x405d,
            ],
    );
}

#[test]
fn test_pack_be_bytes_into_fields() {
    let packed1 = pack_be_bytes_into_fields::<512, _, 15>(TEST_BYTES);
    assert(
        packed1
            == [
                0xa906a6bf52c2d3b6dcc3e53e8df2c2,
                0xa0a652bc1a96ef6fa85aaaac8a2793,
                0xd2aa634a40e786072d1a84a726ee35,
                0x20deee9d92dd32e9d1661cad3fd748,
                0x59c58bff771bcb1007ab5292034b01,
                0xb105cd7c3f8bdffffa8976a1d6712b,
                0x7f04e817f0861ba18ffdc4e9656bd2,
                0xca6ad55f4dc9e1437ae528bff4440b,
                0x0cdf23c048109f118dbc4f062526ec,
                0xc57749fc145d2a6f68c95a0bf1345a,
                0x1744b7ad88a820d428b0f1c79a6660,
                0x21a17ae68fddadbb6d54c97ecbe1e3,
                0x3596b41957a1a78af81fbe9f418d92,
                0x5398a2f749a773190f5d838013b898,
                0xef83111bf9b7819fd12b33ff682590,
                0x56989a6176dfd100ae89dd7936e9f0,
                0x4f3d7ab2e41ba2cb404c3d6cef8740,
                0xc81a370e672704f5f31450f9156d93,
                0x2c9ad440424450b81c303c51d405d3,
                0x5d3aaebc67b2ba64a2f9546349fb9e,
                0xdced3dbea6d67fe49c3f31562ffba7,
                0xa67a19f7fcecb81235e7706b20ecc4,
                0x2fb5c8f5d8ddac8df1c6917eb31bad,
                0xd9478e0dcd3f2ab125ccc6a68c4447,
                0x2ef19aff06bf67ab4226a331ffa737,
                0x5e9ea156076a09e78b919d8c5dee0f,
                0x0b427e9391893f58968fc2d96a2775,
                0x432d27b533c103f1509b4f4fc43ac7,
                0xe0e6d9598280b0aa0f2902b0aa3b3a,
                0xa04da3f98c5cfe8d4d8f9e1fb4e89c,
                0x7e463b5ebaf81c1485efeb44e634f9,
                0xae87ec4262fcfd075f5554475547a3,
                0xfb2297b7ffc0deeb3a1b27effc6b6c,
                0xd3b801cbc8e237620d8dd9adc29551,
                0x405d,
            ],
    );

    let packed2 = pack_be_bytes_into_fields::<512, _, 31>(TEST_BYTES);
    assert(
        packed2
            == [
                0x35a0a652bc1a96ef6fa85aaaac8a2793a906a6bf52c2d3b6dcc3e53e8df2c2,
                0x4b0120deee9d92dd32e9d1661cad3fd748d2aa634a40e786072d1a84a726ee,
                0x656bd2b105cd7c3f8bdffffa8976a1d6712b59c58bff771bcb1007ab529203,
                0x062526ecca6ad55f4dc9e1437ae528bff4440b7f04e817f0861ba18ffdc4e9,
                0xf1c79a6660c57749fc145d2a6f68c95a0bf1345a0cdf23c048109f118dbc4f,
                0x1fbe9f418d9221a17ae68fddadbb6d54c97ecbe1e31744b7ad88a820d428b0,
                0xd12b33ff6825905398a2f749a773190f5d838013b8983596b41957a1a78af8,
                0xcb404c3d6cef874056989a6176dfd100ae89dd7936e9f0ef83111bf9b7819f,
                0x50b81c303c51d405d3c81a370e672704f5f31450f9156d934f3d7ab2e41ba2,
                0xd67fe49c3f31562ffba75d3aaebc67b2ba64a2f9546349fb9e2c9ad4404244,
                0xd8ddac8df1c6917eb31bada67a19f7fcecb81235e7706b20ecc4dced3dbea6,
                0xff06bf67ab4226a331ffa737d9478e0dcd3f2ab125ccc6a68c44472fb5c8f5,
                0x7e9391893f58968fc2d96a27755e9ea156076a09e78b919d8c5dee0f2ef19a,
                0xe6d9598280b0aa0f2902b0aa3b3a432d27b533c103f1509b4f4fc43ac70b42,
                0x7e463b5ebaf81c1485efeb44e634f9a04da3f98c5cfe8d4d8f9e1fb4e89ce0,
                0x51fb2297b7ffc0deeb3a1b27effc6b6cae87ec4262fcfd075f5554475547a3,
                0x405dd3b801cbc8e237620d8dd9adc295,
            ],
    );
}

global TEST_BYTES: [u8; 512] = [
    0x40, 0x5d, 0xd3, 0xb8, 0x01, 0xcb, 0xc8, 0xe2, 0x37, 0x62, 0x0d, 0x8d, 0xd9, 0xad, 0xc2, 0x95,
    0x51, 0xfb, 0x22, 0x97, 0xb7, 0xff, 0xc0, 0xde, 0xeb, 0x3a, 0x1b, 0x27, 0xef, 0xfc, 0x6b, 0x6c,
    0xae, 0x87, 0xec, 0x42, 0x62, 0xfc, 0xfd, 0x07, 0x5f, 0x55, 0x54, 0x47, 0x55, 0x47, 0xa3, 0x7e,
    0x46, 0x3b, 0x5e, 0xba, 0xf8, 0x1c, 0x14, 0x85, 0xef, 0xeb, 0x44, 0xe6, 0x34, 0xf9, 0xa0, 0x4d,
    0xa3, 0xf9, 0x8c, 0x5c, 0xfe, 0x8d, 0x4d, 0x8f, 0x9e, 0x1f, 0xb4, 0xe8, 0x9c, 0xe0, 0xe6, 0xd9,
    0x59, 0x82, 0x80, 0xb0, 0xaa, 0x0f, 0x29, 0x02, 0xb0, 0xaa, 0x3b, 0x3a, 0x43, 0x2d, 0x27, 0xb5,
    0x33, 0xc1, 0x03, 0xf1, 0x50, 0x9b, 0x4f, 0x4f, 0xc4, 0x3a, 0xc7, 0x0b, 0x42, 0x7e, 0x93, 0x91,
    0x89, 0x3f, 0x58, 0x96, 0x8f, 0xc2, 0xd9, 0x6a, 0x27, 0x75, 0x5e, 0x9e, 0xa1, 0x56, 0x07, 0x6a,
    0x09, 0xe7, 0x8b, 0x91, 0x9d, 0x8c, 0x5d, 0xee, 0x0f, 0x2e, 0xf1, 0x9a, 0xff, 0x06, 0xbf, 0x67,
    0xab, 0x42, 0x26, 0xa3, 0x31, 0xff, 0xa7, 0x37, 0xd9, 0x47, 0x8e, 0x0d, 0xcd, 0x3f, 0x2a, 0xb1,
    0x25, 0xcc, 0xc6, 0xa6, 0x8c, 0x44, 0x47, 0x2f, 0xb5, 0xc8, 0xf5, 0xd8, 0xdd, 0xac, 0x8d, 0xf1,
    0xc6, 0x91, 0x7e, 0xb3, 0x1b, 0xad, 0xa6, 0x7a, 0x19, 0xf7, 0xfc, 0xec, 0xb8, 0x12, 0x35, 0xe7,
    0x70, 0x6b, 0x20, 0xec, 0xc4, 0xdc, 0xed, 0x3d, 0xbe, 0xa6, 0xd6, 0x7f, 0xe4, 0x9c, 0x3f, 0x31,
    0x56, 0x2f, 0xfb, 0xa7, 0x5d, 0x3a, 0xae, 0xbc, 0x67, 0xb2, 0xba, 0x64, 0xa2, 0xf9, 0x54, 0x63,
    0x49, 0xfb, 0x9e, 0x2c, 0x9a, 0xd4, 0x40, 0x42, 0x44, 0x50, 0xb8, 0x1c, 0x30, 0x3c, 0x51, 0xd4,
    0x05, 0xd3, 0xc8, 0x1a, 0x37, 0x0e, 0x67, 0x27, 0x04, 0xf5, 0xf3, 0x14, 0x50, 0xf9, 0x15, 0x6d,
    0x93, 0x4f, 0x3d, 0x7a, 0xb2, 0xe4, 0x1b, 0xa2, 0xcb, 0x40, 0x4c, 0x3d, 0x6c, 0xef, 0x87, 0x40,
    0x56, 0x98, 0x9a, 0x61, 0x76, 0xdf, 0xd1, 0x00, 0xae, 0x89, 0xdd, 0x79, 0x36, 0xe9, 0xf0, 0xef,
    0x83, 0x11, 0x1b, 0xf9, 0xb7, 0x81, 0x9f, 0xd1, 0x2b, 0x33, 0xff, 0x68, 0x25, 0x90, 0x53, 0x98,
    0xa2, 0xf7, 0x49, 0xa7, 0x73, 0x19, 0x0f, 0x5d, 0x83, 0x80, 0x13, 0xb8, 0x98, 0x35, 0x96, 0xb4,
    0x19, 0x57, 0xa1, 0xa7, 0x8a, 0xf8, 0x1f, 0xbe, 0x9f, 0x41, 0x8d, 0x92, 0x21, 0xa1, 0x7a, 0xe6,
    0x8f, 0xdd, 0xad, 0xbb, 0x6d, 0x54, 0xc9, 0x7e, 0xcb, 0xe1, 0xe3, 0x17, 0x44, 0xb7, 0xad, 0x88,
    0xa8, 0x20, 0xd4, 0x28, 0xb0, 0xf1, 0xc7, 0x9a, 0x66, 0x60, 0xc5, 0x77, 0x49, 0xfc, 0x14, 0x5d,
    0x2a, 0x6f, 0x68, 0xc9, 0x5a, 0x0b, 0xf1, 0x34, 0x5a, 0x0c, 0xdf, 0x23, 0xc0, 0x48, 0x10, 0x9f,
    0x11, 0x8d, 0xbc, 0x4f, 0x06, 0x25, 0x26, 0xec, 0xca, 0x6a, 0xd5, 0x5f, 0x4d, 0xc9, 0xe1, 0x43,
    0x7a, 0xe5, 0x28, 0xbf, 0xf4, 0x44, 0x0b, 0x7f, 0x04, 0xe8, 0x17, 0xf0, 0x86, 0x1b, 0xa1, 0x8f,
    0xfd, 0xc4, 0xe9, 0x65, 0x6b, 0xd2, 0xb1, 0x05, 0xcd, 0x7c, 0x3f, 0x8b, 0xdf, 0xff, 0xfa, 0x89,
    0x76, 0xa1, 0xd6, 0x71, 0x2b, 0x59, 0xc5, 0x8b, 0xff, 0x77, 0x1b, 0xcb, 0x10, 0x07, 0xab, 0x52,
    0x92, 0x03, 0x4b, 0x01, 0x20, 0xde, 0xee, 0x9d, 0x92, 0xdd, 0x32, 0xe9, 0xd1, 0x66, 0x1c, 0xad,
    0x3f, 0xd7, 0x48, 0xd2, 0xaa, 0x63, 0x4a, 0x40, 0xe7, 0x86, 0x07, 0x2d, 0x1a, 0x84, 0xa7, 0x26,
    0xee, 0x35, 0xa0, 0xa6, 0x52, 0xbc, 0x1a, 0x96, 0xef, 0x6f, 0xa8, 0x5a, 0xaa, 0xac, 0x8a, 0x27,
    0x93, 0xa9, 0x06, 0xa6, 0xbf, 0x52, 0xc2, 0xd3, 0xb6, 0xdc, 0xc3, 0xe5, 0x3e, 0x8d, 0xf2, 0xc2,
];

/// ASN.1 functions

#[test]
fn test_unsafe_get_asn1_element_length() {
    let long_form_asn1_seq: [u8; _] = [
        0x30, 0x82, 0x01, 0xc8, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x09, 0xba, 0xc5, 0xe1,
        0xbc, 0x40, 0x1a, 0xd9, 0xd4, 0x53, 0x95, 0xbc, 0x38, 0x1a, 0x08, 0x54, 0x30, 0x0a, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x52, 0x31, 0x26, 0x30, 0x24,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1d, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20, 0x41, 0x70,
        0x70, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x52,
        0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x0a, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x13, 0x30,
        0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72,
        0x6e, 0x69, 0x61, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x33, 0x31, 0x38, 0x31, 0x38,
        0x33, 0x39, 0x35, 0x35, 0x5a, 0x17, 0x0d, 0x33, 0x30, 0x30, 0x33, 0x31, 0x33, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x4f, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x1a, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20, 0x41, 0x70, 0x70, 0x20, 0x41, 0x74,
        0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x43, 0x41, 0x20, 0x31, 0x31,
        0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0a, 0x41, 0x70, 0x70, 0x6c, 0x65,
        0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
        0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x30, 0x76, 0x30, 0x10,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00,
        0x22, 0x03, 0x62, 0x00, 0x04, 0xae, 0x5b, 0x37, 0xa0, 0x77, 0x4d, 0x79, 0xb2, 0x35, 0x8f,
        0x40, 0xe7, 0xd1, 0xf2, 0x26, 0x26, 0xf1, 0xc2, 0x5f, 0xef, 0x17, 0x80, 0x2d, 0xea, 0xb3,
        0x82, 0x6a, 0x59, 0x87, 0x4f, 0xf8, 0xd2, 0xad, 0x15, 0x25, 0x78, 0x9a, 0xa2, 0x66, 0x04,
        0x19, 0x12, 0x48, 0xb6, 0x3c, 0xb9, 0x67, 0x06, 0x9e, 0x98, 0xd3, 0x63, 0xbd, 0x5e, 0x37,
        0x0f, 0xbf, 0xa0, 0x8e, 0x32, 0x9e, 0x80, 0x73, 0xa9, 0x85, 0xe7, 0x74, 0x6e, 0xa3, 0x59,
        0xa2, 0xf6, 0x6f, 0x29, 0xdb, 0x32, 0xaf, 0x45, 0x5e, 0x21, 0x16, 0x58, 0xd5, 0x67, 0xaf,
        0x9e, 0x26, 0x7e, 0xb2, 0x61, 0x4d, 0xc2, 0x1a, 0x66, 0xce, 0x99, 0xa3, 0x66, 0x30, 0x64,
        0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01,
        0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,
        0x16, 0x80, 0x14, 0xac, 0x91, 0x10, 0x53, 0x33, 0xbd, 0xbe, 0x68, 0x41, 0xff, 0xa7, 0x0c,
        0xa9, 0xe5, 0xfa, 0xea, 0xe5, 0xe5, 0x8a, 0xa1, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
        0x04, 0x16, 0x04, 0x14, 0x3e, 0xe3, 0x5d, 0x1c, 0x04, 0x19, 0xa9, 0xc9, 0xb4, 0x31, 0xf8,
        0x84, 0x74, 0xd6, 0xe1, 0xe1, 0x57, 0x72, 0xe3, 0x9b, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
        0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // 0x30 0x03 = SEQUENCE with 3 bytes of content
    // Total length should be 5 (tag + length + content)
    let short_form_asn1_seq: [u8; 10] =
        [0x30, 0x03, 0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00];

    // Test with a long form example
    // Safety:
    let len = unsafe { unsafe_get_asn1_element_length(long_form_asn1_seq) };
    assert(len == 460);
    // Test with a short form example
    // Safety:
    let short_parsed_length = unsafe { unsafe_get_asn1_element_length(short_form_asn1_seq) };
    assert(short_parsed_length == 5);
}

/// Find subarray index functions

#[test]
fn test_find_subarray_index_various_cases() {
    // Test case 1: Basic substring at index 3
    let needle1 = [0x04, 0x05, 0x06];
    let haystack1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
    let index1 = find_subarray_index(needle1, haystack1);
    assert_eq(index1, 3);

    // Test case 2: Substring at the beginning
    let needle2 = [0x01, 0x02];
    let haystack2 = [0x01, 0x02, 0x03, 0x04, 0x05];
    let index2 = find_subarray_index(needle2, haystack2);
    assert_eq(index2, 0);

    // Test case 3: Substring at the end
    let needle3 = [0x04, 0x05];
    let haystack3 = [0x01, 0x02, 0x03, 0x04, 0x05];
    let index3 = find_subarray_index(needle3, haystack3);
    assert_eq(index3, 3);

    // Test case 4: Single byte needle
    let needle4 = [0x03];
    let haystack4 = [0x01, 0x02, 0x03, 0x04, 0x05];
    let index4 = find_subarray_index(needle4, haystack4);
    assert_eq(index4, 2);

    // Test case 5: Empty needle (should return 0)
    let needle5: [u8; 0] = [];
    let haystack5 = [0x01, 0x02, 0x03, 0x04, 0x05];
    let index5 = find_subarray_index(needle5, haystack5);
    assert_eq(index5, 0);

    // Test case 6: Needle not found - completely different bytes
    let needle6 = [0xff, 0xee, 0xdd];
    let haystack6 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
    let index6 = find_subarray_index(needle6, haystack6);
    assert_eq(index6, haystack6.len()); // Should equal haystack size

    // Test case 7: Needle larger than haystack
    let needle7 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let haystack7 = [0x01, 0x02, 0x03];
    let index7 = find_subarray_index(needle7, haystack7);
    assert_eq(index7, haystack7.len()); // Should equal haystack size

    // Test case 8: Partial match at the end but incomplete
    let needle8 = [0x09, 0x0a, 0x0b];
    let haystack8 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
    let index8 = find_subarray_index(needle8, haystack8);
    assert_eq(index8, haystack8.len()); // Should equal haystack size

    // Test case 9: Multiple false matches (partial matches)
    let needle9 = [0x01, 0x01, 0x02];
    let haystack9 = [0x01, 0x03, 0x01, 0x04, 0x01, 0x01, 0x03, 0x05, 0x06, 0x07];
    let index9 = find_subarray_index(needle9, haystack9);
    assert_eq(index9, haystack9.len()); // Should equal haystack size

    // Test case 10: Needle appears to match but fails verification
    let needle10 = [0x02, 0x03, 0x04];
    let haystack10 = [0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09];
    let index10 = find_subarray_index(needle10, haystack10);
    assert_eq(index10, haystack10.len()); // Should equal haystack size
}

pub fn verify_subarray_in_array<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) {
    let offset = find_subarray_index(needle, haystack);
    assert(offset < HAYSTACK_SIZE, "Needle not found in haystack")
}

#[test]
fn test_verify_subarray_in_array() {
    let needle = [0x04, 0x05, 0x06];
    let haystack = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
    verify_subarray_in_array(needle, haystack);
}

/// Miscellaneous functions

#[test]
fn test_split_array() {
    let array = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let (array_x, array_y) = split_array(array);
    assert_eq(array_x, [0x01, 0x02, 0x03]);
    assert_eq(array_y, [0x04, 0x05, 0x06]);
}

#[test]
fn test_check_zero_padding() {
    let array = [0x01, 0x02, 0x03, 0, 0, 0];
    check_zero_padding(array, 3);
}

#[test(should_fail_with = "Array is not zero-padded")]
fn test_check_zero_padding_fail() {
    let array = [0x01, 0x02, 0x03, 0, 0, 0x06];
    check_zero_padding(array, 3);
}

#[test]
fn test_pack_be_bit_into_field() {
    let mut x = [0 as u1; 90];
    x[0] = 1;
    x[1] = 1;
    x[2] = 1;
    let result = pack_be_bit_into_field::<90>(x);
    assert_eq(result, 0x038000000000000000000000);
}

#[test]
fn test_salted_value_hash_from_value() {
    let salted_value = SaltedValue::from_value(3, 1);
    let hash = salted_value.get_hash();
    assert_eq(hash, 0x2a9211c39ebf603ec089e2340d71642e179fcd1f736790ed26fa669c7a142c5e);
}

#[test]
fn test_salted_value_hash_from_hash() {
    let salted_value: SaltedValue<u32> = SaltedValue::from_hash(
        0x2a9211c39ebf603ec089e2340d71642e179fcd1f736790ed26fa669c7a142c5e,
    );
    let hash = salted_value.get_hash();
    assert_eq(hash, 0x2a9211c39ebf603ec089e2340d71642e179fcd1f736790ed26fa669c7a142c5e);
}

#[test(should_fail_with = "Salt must be non-zero when computing the hash from a clear value and its salt")]
fn test_salted_value_hash_from_value_zero_salt() {
    let salted_value = SaltedValue { salt: 0, value: 1, hash: 0 };
    let hash = salted_value.get_hash();
}

#[test(should_fail_with = "Value must be non-zero when computing the hash from a clear value and its salt")]
fn test_salted_value_hash_from_value_zero_value() {
    let salted_value = SaltedValue { salt: 1, value: 0, hash: 0 };
    let hash = salted_value.get_hash();
}

#[test(should_fail_with = "Salt cannot be 0 when creating a salted value from a clear value")]
fn test_salted_value_from_value_zero_salt() {
    let salted_value = SaltedValue::from_value(0, 1);
}

#[test(should_fail_with = "Value cannot be the default value when creating a salted value from a clear value")]
fn test_salted_value_from_value_default_value() {
    let salted_value = SaltedValue::from_value(1, 0);
}

#[test(should_fail_with = "Hash cannot be 0 when creating a salted value from a hash")]
fn test_salted_value_from_hash_zero_hash() {
    let salted_value: SaltedValue<u32> = SaltedValue::from_hash(0);
}

#[test(should_fail_with = "Salt must be 0 when hash is already specified")]
fn test_salted_value_hash_from_hash_zero_hash() {
    let salted_value = SaltedValue { salt: 1, value: 1, hash: 1 };
    let hash = salted_value.get_hash();
}

/// MRZ getters

#[test]
fn test_get_name_passport() {
    // name = 'Doe<<John<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<',
    let name = [
        68, 111, 101, 60, 60, 74, 111, 104, 110, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
        60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
    ];
    let dg1 = DG1Builder::new([0; 95]).with_name(name).build();

    let mrz_name = get_name_from_mrz(dg1);
    assert_eq(mrz_name, name);
}

#[test]
fn test_get_name_id_card() {
    // name = 'Doe<<John<<<<<<<<<<<<<<<<<<<<<',
    let name = [
        68, 111, 101, 60, 60, 74, 111, 104, 110, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
        60, 60, 60, 60, 60, 60, 60, 60,
    ];
    // padded_name = 'Doe<<John<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<',
    let padded_name = [
        68, 111, 101, 60, 60, 74, 111, 104, 110, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
        60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
    ];

    let dg1 = DG1Builder::new([0; 95]).set_is_id_card().with_name_id_card(name).build();
    let mrz_name = get_name_from_mrz(dg1);
    assert_eq(mrz_name, padded_name);
}

#[test]
fn test_get_nationality_passport() {
    let mrz_nationality = get_nationality_from_mrz(SAMPLE_DG1);
    assert_eq(mrz_nationality, "AUS".as_bytes());
}

#[test]
fn test_get_nationality_id_card() {
    let mrz_nationality = get_nationality_from_mrz(EXTENDED_ID_CARD_SAMPLE_DG1);
    assert_eq(mrz_nationality, "PRT".as_bytes());
}

#[test]
fn test_get_issuing_country_passport() {
    let mrz_issuing_country = get_issuing_country_from_mrz(SAMPLE_DG1);
    assert_eq(mrz_issuing_country, "AUS".as_bytes());
}

#[test]
fn test_get_issuing_country_id_card() {
    let mrz_issuing_country = get_issuing_country_from_mrz(EXTENDED_ID_CARD_SAMPLE_DG1);
    assert_eq(mrz_issuing_country, "PRT".as_bytes());
}

#[test]
fn test_get_dob_passport() {
    let mrz_dob = get_dob_from_mrz(SAMPLE_DG1);
    assert_eq(mrz_dob, "881112".as_bytes());
}

#[test]
fn test_get_dob_id_card() {
    let mrz_dob = get_dob_from_mrz(EXTENDED_ID_CARD_SAMPLE_DG1);
    assert_eq(mrz_dob, "830314".as_bytes());
}

#[test]
fn test_get_yob_passport() {
    let mrz_yob = get_yob_from_mrz(SAMPLE_DG1);
    assert_eq(mrz_yob, "88".as_bytes());
}

#[test]
fn test_get_yob_id_card() {
    let mrz_yob = get_yob_from_mrz(EXTENDED_ID_CARD_SAMPLE_DG1);
    assert_eq(mrz_yob, "83".as_bytes());
}

#[test]
fn test_get_expiry_date_passport() {
    let mrz_expiry_date = get_expiry_date_from_mrz(SAMPLE_DG1);
    assert_eq(mrz_expiry_date, "300101".as_bytes());
}

#[test]
fn test_get_expiry_date_id_card() {
    let mrz_expiry_date = get_expiry_date_from_mrz(EXTENDED_ID_CARD_SAMPLE_DG1);
    assert_eq(mrz_expiry_date, "340529".as_bytes());
}

#[test]
fn test_get_document_number_passport() {
    let mrz_document_number = get_document_number_from_mrz(SAMPLE_DG1);
    assert_eq(mrz_document_number, "PA1234567".as_bytes());
}

#[test]
fn test_get_document_number_id_card() {
    let mrz_document_number = get_document_number_from_mrz(ID_CARD_SAMPLE_DG1);
    assert_eq(mrz_document_number, "ZID222222".as_bytes());
}

// TODO: Add a test for the extended document number
// once get_document_number_from_mrz can extract the whole extended document number
