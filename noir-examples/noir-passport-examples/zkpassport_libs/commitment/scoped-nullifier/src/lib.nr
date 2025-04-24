use common::{calculate_scoped_nullifier, hash_salt_dg1_private_nullifier};

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
    assert(comm_in == hash_salt_dg1_private_nullifier(salt, dg1, private_nullifier));
    // println(f"comm_in: {comm_in}");
    let scoped_nullifier =
        calculate_scoped_nullifier(private_nullifier, service_scope, service_subscope);
    // println(f"scoped_nullifier: {scoped_nullifier}");
    scoped_nullifier
}

