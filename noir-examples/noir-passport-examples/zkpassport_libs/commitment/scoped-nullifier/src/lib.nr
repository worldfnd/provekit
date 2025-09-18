use common::{calculate_scoped_nullifier, hash_salt_dg1_private_nullifier};
use utils::get_issuing_country_from_mrz;

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
    salt: Field,
    dg1: [u8; 95],
    private_nullifier: Field,
    service_scope: Field,
    service_subscope: Field,
) -> Field {
    assert(
        comm_in == hash_salt_dg1_private_nullifier(salt, dg1, private_nullifier),
        "Commitment from 3rd subproof doesn't match in disclosure proof",
    );
    let mut scoped_nullifier =
        calculate_scoped_nullifier(private_nullifier, service_scope, service_subscope);
    let issuing_country = get_issuing_country_from_mrz(dg1);
    // Doesn't matter if we already calculated the scoped nullifier above
    // cause it's ZK all branches will be evaluated anyway
    if issuing_country == ZKR_COUNTRY_CODE_BYTES {
        // Set the scoped nullifier to 1 to indicate the issuing country is not a real one
        // and prevent the use of these proofs in production
        // Note: ZKPassport's registries on mainnet blockchains will not include
        // the ZKR certificates but still this distinction can be useful for testnets/devnets
        scoped_nullifier = 1;
    }
    scoped_nullifier
}
