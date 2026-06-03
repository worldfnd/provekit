use bignum::BigNum;

unconstrained fn hash_to_curve_inner<Fq>(
    seedbase: Field,
    seed_counter: Field,
    a: Fq,
    b: Fq,
) -> (Fq, Fq, Field)
where
    Fq: BigNum,
{
    let seedhash = poseidon::poseidon2::Poseidon2::hash([seedbase, seed_counter], 2);
    // TODO: assert in field?
    let seedhash: [u8; 32] = seedhash.to_le_bytes();

    let x = Fq::derive_from_seed(seedhash);

    let yy = x * x * x + a * x + b;
    yy.validate_in_field();
    yy.validate_in_range();
    x.validate_in_field();
    x.validate_in_range();
    let y = yy.__tonelli_shanks_sqrt();
    let yy_reconstructed = y.unwrap_unchecked() * y.unwrap_unchecked();
    let mut result: (Fq, Fq, Field) = (x, y.unwrap_unchecked(), seed_counter);
    if (((yy_reconstructed == yy) & (y.is_some())) == false) {
        result = hash_to_curve_inner(seedbase, seed_counter + 1, a, b);
    }
    if (y.is_some()) {
        y.unwrap_unchecked().validate_in_field();
        y.unwrap_unchecked().validate_in_range();
    }
    result
}

unconstrained fn __hash_to_curve_witgen<Fq, let SeedBytes: u32>(
    seed: [u8; SeedBytes],
    a: Fq,
    b: Fq,
) -> (Fq, Fq, Field)
where
    Fq: BigNum,
{
    let hashed_seed = poseidon_hash_bytes(seed);
    hash_to_curve_inner(hashed_seed, 0, a, b)
}

fn poseidon_hash_bytes<let SeedBytes: u32>(seed: [u8; SeedBytes]) -> Field {
    let mut padded_seed: [u8; (SeedBytes / 31 + 1) * 31] = [0; (SeedBytes / 31 + 1) * 31];
    for i in 0..SeedBytes {
        padded_seed[i] = seed[i];
    }
    let packed_seed: [Field; SeedBytes / 31 + 1] = [0; SeedBytes / 31 + 1];
    for i in 0..SeedBytes / 31 + 1 {
        let mut packed: Field = 0;
        for _ in 0..31 {
            packed *= 256;
            packed += padded_seed[i] as Field;
        }
    }
    let hashed_seed: Field = poseidon::poseidon2::Poseidon2::hash(packed_seed, SeedBytes / 31 + 1);
    hashed_seed
}
pub fn hash_to_curve<Fq, let SeedBytes: u32>(seed: [u8; SeedBytes], a: Fq, b: Fq) -> (Fq, Fq)
where
    Fq: BigNum,
{
    let (_, y, salt) = unsafe { __hash_to_curve_witgen(seed, a, b) };
    let outer_hash: Field = poseidon_hash_bytes(seed);

    let inner_hash = poseidon::poseidon2::Poseidon2::hash([outer_hash, salt], 2);

    // TODO do we need to assert is in field?; I think we do?
    let inner_hash: [u8; 32] = inner_hash.to_le_bytes();
    let x = Fq::derive_from_seed(inner_hash);
    let yy = x * x * x + a * x + b;
    assert(y * y == yy);

    let parity_flag = (inner_hash[0] & 1) == 1;

    let negated_y = y.neg();
    let output_y = if parity_flag { y } else { negated_y };

    x.validate_in_field();
    x.validate_in_range();
    output_y.validate_in_field();
    output_y.validate_in_range();
    (x, output_y)
}
