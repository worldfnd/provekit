use super::types::{OprfQueryInputs, PublicKey};

pub fn oprf_query(inputs: OprfQueryInputs, query: Field) -> PublicKey {
    PublicKey { x: 0, y: 0 }
}

pub fn unblind_oprf_response(blinded_response: PublicKey, beta: Field, query: Field) -> PublicKey {
    PublicKey { x: 0, y: 0 }
}
