use dep::poseidon2;

fn hash_variable_input(input: [Field]) -> Field {
    let input_size = input.len();
    // Number of permutation events needed (ceiling of input_size/3)
    let num_perm_events = (input_size + 2) / 3;

    // Initial state with IV (input length) in last position
    // Note: << 64 in Noir would be done differently, using field arithmetic
    let iv = input_size as Field; // Simplified IV for example
    let mut perm_state = [0, 0, 0, iv];

    // Process input in chunks of 3
    let mut processed = 0;
    for _i in 0..num_perm_events {
        // Determine chunk size (3 or remaining elements)
        let chunk_size = if input_size - processed >= 3 {
            3
        } else {
            input_size - processed
        };

        // Absorb input chunk into state
        for j in 0..chunk_size {
            perm_state[j] = perm_state[j] + input[processed + j];
        }

        // Apply permutation (using x5_4 as it handles 4-element state)
        perm_state = poseidon2::bn254::perm::x5_4(perm_state);

        processed += chunk_size;
    }

    // Return first element as hash result
    perm_state[0]
}

fn main(plains: [Field; 16], result: Field) {
    let hash = hash_variable_input(plains);
    print(hash);
    assert(hash == result);
}
