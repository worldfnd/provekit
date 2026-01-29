use common::{hash_salt_dg1_private_nullifier, calculate_scoped_nullifier};
use utils::{
    constants::{
        NON_SALTED_MOCK_NULLIFIER, NON_SALTED_NULLIFIER, SALTED_MOCK_NULLIFIER, SALTED_NULLIFIER,
    },
    get_issuing_country_from_mrz,
    types::{DG1Data, MRZExpiryDate, SaltedValue},
};

// The ZKR (or Zero Knowledge Republic) is a mock country used for testing purposes
global ZKR_COUNTRY_CODE_BYTES: [u8; 3] = [90, 75, 82];

/*
############################################################
# Circuit D
############################################################
# Generates a scoped nullifier that is scoped by service
# Allows selective disclosure of dg1 via a reveal bitmask
############################################################

# Inputs/Outputs
############################################################
comm_in             `assert comm_in == H(salt, dg1, private_nullifier)`
salt
dg1
private_nullifier
service_scope       `H(<domain_name>)`
service_subscope    `H(<purpose>)` (Service-specific subscope)
scoped_nullifier    `H(private_nullifier, service_scope, service_subscope)`

# Checks
############################################################
- Checks that dg1_reveal is the correct reveal of dg1 for the given dg1_mask
- Constrains scoped_nullifier to be `H(private_nullifier, service_scope, service_subscope)`
*/
pub fn nullify(
    comm_in: Field,
    salted_dg1: SaltedValue<DG1Data>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_private_nullifier: SaltedValue<Field>,
    service_scope: Field,
    service_subscope: Field,
    nullifier_secret: Field,
) -> (Field, Field) {
    assert(
        comm_in
            == hash_salt_dg1_private_nullifier(
                salted_dg1,
                salted_expiry_date,
                salted_private_nullifier,
            ),
        "Commitment from 3rd subproof doesn't match in disclosure proof",
    );
    let mut scoped_nullifier = calculate_scoped_nullifier(
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    // Determine the nullifier type based on the secret
    let mut nullifier_type = if nullifier_secret != 0 {
        // Set the nullifier type to the salted nullifier type
        // as the secret was used to salt the nullifier
        SALTED_NULLIFIER
    } else {
        // Set the nullifier type to the non-salted nullifier type
        // as the secret was not used to salt the nullifier
        NON_SALTED_NULLIFIER
    };
    let issuing_country = get_issuing_country_from_mrz(salted_dg1.value);
    // Doesn't matter if we already calculated the scoped nullifier above
    // cause it's ZK all branches will be evaluated anyway
    if issuing_country == ZKR_COUNTRY_CODE_BYTES {
        // Set the nullifier type to one of the mock nullifier types
        // to indicate the issuing country is not a real one
        // and prevent the use of these proofs in production
        // Note: ZKPassport's registries on mainnet blockchains will not include
        // the ZKR certificates but still this distinction can be useful for testnets/devnets
        if nullifier_secret != 0 {
            // Set the nullifier type to the salted mock nullifier type
            // as the secret was used to salt the nullifier
            nullifier_type = SALTED_MOCK_NULLIFIER;
        } else {
            // Set the nullifier type to the non-salted mock nullifier type
            // as the secret was not used to salt the nullifier
            nullifier_type = NON_SALTED_MOCK_NULLIFIER;
        }
    }
    (scoped_nullifier, nullifier_type)
}
