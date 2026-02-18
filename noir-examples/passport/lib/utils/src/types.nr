use super::constants::{
    DG1_LENGTH, ECONTENT_LENGTH, MAX_MRZ_LENGTH, PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH,
    PASSPORT_MRZ_NATIONALITY_LENGTH, SHA1_DIGEST_LENGTH, SHA224_DIGEST_LENGTH, SHA256_DIGEST_LENGTH,
    SHA384_DIGEST_LENGTH, SHA512_DIGEST_LENGTH, SIGNED_ATTRS_LENGTH, YYMMDD_DATE_LENGTH,
};
use super::pack_be_bytes_into_fields;
use poseidon::poseidon2::Poseidon2;

// DG1 types
pub type DG1Data = [u8; DG1_LENGTH];
pub type MRZData = [u8; MAX_MRZ_LENGTH];

// Dates
pub type YYYYMMDDDate = [u8; YYMMDD_DATE_LENGTH];
pub type YYMMDDDate = [u8; YYMMDD_DATE_LENGTH];

// MRZ types
pub type MRZName = [u8; 39];
pub type MRZNameIdCard = [u8; 30];
pub type MRZDOB = YYMMDDDate;
pub type MRZYOB = [u8; 2];
pub type MRZExpiryDate = YYMMDDDate;
pub type MRZDocumentNumber = [u8; 9];
pub type MRZNationality = [u8; PASSPORT_MRZ_NATIONALITY_LENGTH];
pub type MRZIssuingCountry = [u8; PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH];

pub type EContentData = [u8; ECONTENT_LENGTH];
pub type SignedAttrsData = [u8; SIGNED_ATTRS_LENGTH];

pub type Alpha3CountryCode = str<3>;
pub type Alpha2CountryCode = str<2>;

pub type DiscloseMask = [u1; MAX_MRZ_LENGTH];

pub type SHA1Digest = [u8; SHA1_DIGEST_LENGTH];
pub type SHA224Digest = [u8; SHA224_DIGEST_LENGTH];
pub type SHA256Digest = [u8; SHA256_DIGEST_LENGTH];
pub type SHA384Digest = [u8; SHA384_DIGEST_LENGTH];
pub type SHA512Digest = [u8; SHA512_DIGEST_LENGTH];

/// This struct acts as a wrapper around a value, so it can be specified as either a clear value with
/// a provided salt for hashing or only as its salted hash if its clear value is not needed inside the circuit
pub struct SaltedValue<T> {
    pub salt: Field,
    pub value: T,
    pub hash: Field,
}

impl<T> Default for SaltedValue<T>
where
    T: Default,
{
    fn default() -> Self {
        Self { salt: 0, value: T::default(), hash: 0 }
    }
}

impl<T> SaltedValue<T>
where
    T: Default,
    T: Eq,
{
    /// When the clear value is needed inside the circuit, use this method to create a salted value
    pub fn from_value(salt: Field, value: T) -> Self {
        assert(salt != 0, "Salt cannot be 0 when creating a salted value from a clear value");
        assert(
            value != T::default(),
            "Value cannot be the default value when creating a salted value from a clear value",
        );
        Self { salt, value, hash: 0 }
    }

    /// When the clear value is not needed and is better hidden, use this method to specify the hash only
    pub fn from_hash(hash: Field) -> Self {
        assert(hash != 0, "Hash cannot be 0 when creating a salted value from a hash");
        Self { salt: 0, value: T::default(), hash }
    }
}

impl SaltedValue<u32> {
    /// Gets the salted hash of the value
    /// If the hash is already specified, it will return the hash directly
    /// Otherwise, it will compute the hash from the salt and value
    pub fn get_hash(self) -> Field {
        if self.hash != 0 {
            assert_eq(self.salt, 0, "Salt must be 0 when hash is already specified");
            assert_eq(self.value, 0, "Value must be 0 when hash is already specified");
            self.hash
        } else {
            assert(
                self.value != 0,
                "Value must be non-zero when computing the hash from a clear value and its salt",
            );
            assert(
                self.salt != 0,
                "Salt must be non-zero when computing the hash from a clear value and its salt",
            );
            Poseidon2::hash([self.salt, self.value as Field], 2)
        }
    }
}

impl SaltedValue<Field> {
    /// Gets the salted hash of the value
    /// If the hash is already specified, it will return the hash directly
    /// Otherwise, it will compute the hash from the salt and value
    pub fn get_hash(self) -> Field {
        if self.hash != 0 {
            assert_eq(self.salt, 0, "Salt must be 0 when hash is already specified");
            assert_eq(self.value, 0, "Value must be 0 when hash is already specified");
            self.hash
        } else {
            assert(
                self.value != 0,
                "Value must be non-zero when computing the hash from a clear value and its salt",
            );
            assert(
                self.salt != 0,
                "Salt must be non-zero when computing the hash from a clear value and its salt",
            );
            Poseidon2::hash([self.salt, self.value], 2)
        }
    }
}

impl<let N: u32> SaltedValue<[u8; N]> {
    /// Gets the salted hash of the value
    /// If the hash is already specified, it will return the hash directly
    /// Otherwise, it will compute the hash from the salt and value
    pub fn get_hash(self) -> Field {
        if self.hash != 0 {
            assert_eq(self.salt, 0, "Salt must be 0 when hash is already specified");
            assert_eq(self.value, [0; N], "Value must be zeroed when hash is already specified");
            self.hash
        } else {
            assert(
                self.value != [0; N],
                "Value must be non-zeroed when computing the hash from a clear value and its salt",
            );
            assert(
                self.salt != 0,
                "Salt must be non-zero when computing the hash from a clear value and its salt",
            );
            let packed_value: [Field; (N + 30) / 31] =
                pack_be_bytes_into_fields::<N, _, 31>(self.value);
            Poseidon2::hash([self.salt].concat(packed_value), (N + 30) / 31 + 1)
        }
    }
}
