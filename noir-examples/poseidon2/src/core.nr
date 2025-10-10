use super::poseidon2_constants;

// S-box: x^5
fn sbox_e(x: Field) -> Field {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

// Apply S-box to all elements
fn sbox<let T: u32>(state: [Field; T]) -> [Field; T]{
    let mut out = state;
    for i in 0..T {
        out[i] = sbox_e(state[i]);
    }
    out
}

// Accumulate sum of a vector 
fn acc<let T: u32>(xs: [Field; T]) -> Field {
    let mut s = xs[0];
    for i in 1..T { s += xs[i]; }
    s
}

// External MDS 
fn external_matmul2(in_: [Field; 2]) -> [Field; 2] {
    let sum = in_[0] + in_[1];
    [ in_[0] + sum, in_[1] + sum ]
}

fn external_matmul3(in_: [Field; 3]) -> [Field; 3] {
    let sum = in_[0] + in_[1] + in_[2];
    [ in_[0] + sum, in_[1] + sum, in_[2] + sum ]
}

fn external_matmul4(in_: [Field; 4]) -> [Field; 4] {
    let double_in1 = 2 * in_[1];
    let double_in3 = 2 * in_[3];

    let t0 = in_[0] + in_[1];
    let t1 = in_[2] + in_[3];

    let quad_t0 = 4 * t0;
    let quad_t1 = 4 * t1;

    let t2 = double_in1 + t1;
    let t3 = double_in3 + t0;
    let t4 = quad_t1 + t3;
    let t5 = quad_t0 + t2;

    [ t3 + t5, t5, t2 + t4, t4 ]
}

// Generalized external matmul for T in {2,3,4,8,12,16}
fn external_matmul_t<let T: u32>(input: [Field; T]) -> [Field; T] {
  
    let out_mut: [Field; T] =
    if T == 2 {  external_matmul2([input[0], input[1]]) }
    else if T == 3 {  external_matmul3([input[0], input[1], input[2]]) }
    else if T == 4 {  external_matmul4([input[0], input[1], input[2], input[3]]) }

    else if T == 8 {
            // BLOCKS = 2
            let mut block_out: [[Field; 4]; 2] =
                [[0 as Field, 0 as Field, 0 as Field, 0 as Field]; 2];

            for i in 0..2 {
                block_out[i] = external_matmul4([
                    input[4*i + 0],
                    input[4*i + 1],
                    input[4*i + 2],
                    input[4*i + 3],
                ]);
            }

            let mut col_acc: [Field; 4] = [0 as Field, 0 as Field, 0 as Field, 0 as Field];
            for j in 0..4 {
                let mut col: [Field; 2] = [0 as Field; 2];
                for i in 0..2 { col[i] = block_out[i][j]; }
                col_acc[j] = acc::<2>(col);
            }

            let mut out_mut: [Field; 8] = input;
            for i in 0..2 {
                for j in 0..4 {
                    out_mut[4*i + j] = block_out[i][j] + col_acc[j];
                }
            }
            out8
        } else if T == 12 {
            // BLOCKS = 3
            let mut block_out: [[Field; 4]; 3] =
                [[0 as Field, 0 as Field, 0 as Field, 0 as Field]; 3];

            for i in 0..3 {
                block_out[i] = external_matmul4([
                    input[4*i + 0],
                    input[4*i + 1],
                    input[4*i + 2],
                    input[4*i + 3],
                ]);
            }

            let mut col_acc: [Field; 4] = [0 as Field, 0 as Field, 0 as Field, 0 as Field];
            for j in 0..4 {
                let mut col: [Field; 3] = [0 as Field; 3];
                for i in 0..3 { col[i] = block_out[i][j]; }
                col_acc[j] = acc::<3>(col);
            }

            let mut out_mut: [Field; 12] = input;
            for i in 0..3 {
                for j in 0..4 {
                    out_mut[4*i + j] = block_out[i][j] + col_acc[j];
                }
            }
            out12
        } else {
            // T == 16, BLOCKS = 4
            let mut block_out: [[Field; 4]; 4] =
                [[0 as Field, 0 as Field, 0 as Field, 0 as Field]; 4];

            for i in 0..4 {
                block_out[i] = external_matmul4([
                    input[4*i + 0],
                    input[4*i + 1],
                    input[4*i + 2],
                    input[4*i + 3],
                ]);
            }

            let mut col_acc: [Field; 4] = [0 as Field, 0 as Field, 0 as Field, 0 as Field];
            for j in 0..4 {
                let mut col: [Field; 4] = [0 as Field; 4];
                for i in 0..4 { col[i] = block_out[i][j]; }
                col_acc[j] = acc::<4>(col);
            }

            let mut out_mut: [Field; 16] = input;
            for i in 0..4 {
                for j in 0..4 {
                    out_mut[4*i + j] = block_out[i][j] + col_acc[j];
                }
            }
            out16
        };

    out_mut
}


// Internal MDS for partial rounds
fn internal_matmul2(in_: [Field; 2]) -> [Field; 2] {
    let sum = in_[0] + in_[1];
    [ in_[0] + sum, 2*in_[1] + sum ]
}

fn internal_matmul3(in_: [Field; 3]) -> [Field; 3] {
    let sum = in_[0] + in_[1] + in_[2];
    [ in_[0] + sum, in_[1] + sum, 2*in_[2] + sum ]
}

// diag loader must come from constants for each T > 3
fn internal_matmul_t<let T: u32>(input: [Field; T]) -> [Field; T] {
    if T == 2 {  internal_matmul2([input[0], input[1]]); }
   else if T == 3 { internal_matmul3([input[0], input[1], input[2]]); }
else {
    let diag: [Field; T] = load_diag::<T>();   // from constants
    let sum_all = acc(input);
    let mut out = input;
    for i in 0..T {
        out[i] = input[i] * diag[i] + sum_all;
    }
    out
}
}

// Full & Partial rounds 
fn full_round<let T: u32>(state: [Field; T], rc: [Field; T]) -> [Field; T] {
    // add round constants
    let mut lin = state;
    for i in 0..T { lin[i] = state[i] + rc[i]; }

    // sbox on all lanes
    let s = sbox::<T>(lin);

    // external MDS
    external_matmul_t::<T>(s)
}

fn partial_round<let T: u32>(state: [Field; T], rc_first_lane: Field) -> [Field; T] {
    // add rc to first lane + sbox on first lane
    let mut next = state;
    next[0] = sbox_e(state[0] + rc_first_lane);

    // internal MDS
    internal_matmul_t::<T>(next)
}
pub fn poseidon2_permute<let T: u32>(input: [Field; T]) -> [Field; T] {
    // sanity check: allowed widths
       let valid = (T == 2) | (T == 3) | (T == 4) | (T == 8) | (T == 12) | (T == 16);
    assert(valid);
if T==2 {
    let pr = poseidon2_constants::amount_partial_rounds(2);
    let rc_full1  = poseidon2_constants::load_rc_full1(2);
    let rc_partial   = poseidon2_constants::load_rc_partial(2);
    let rc_full2= poseidon2_constants::load_rc_full2(2);
} else if T==3 {
    let pr = poseidon2_constants::amount_partial_rounds(3);
    let rc_full1 = poseidon2_constants::load_rc_full1(3);
    let rc_partial = poseidon2_constants::load_rc_partial(3);
    let rc_full2 = poseidon2_constants::load_rc_full2(3);
} else if T==4 {
    let pr = poseidon2_constants::amount_partial_rounds(4);
    let rc_full1 = poseidon2_constants::load_rc_full1(4);
    let rc_partial = poseidon2_constants::load_rc_partial(4);
    let rc_full2 = poseidon2_constants::load_rc_full2(4);
} else if T==8 {
    let pr = poseidon2_constants::amount_partial_rounds(8);
    let rc_full1 = poseidon2_constants::load_rc_full1(8);
    let rc_partial = poseidon2_constants::load_rc_partial(8);
    let rc_full2 = poseidon2_constants::load_rc_full2(8);
} else if T==12 {
    let pr = poseidon2_constants::amount_partial_rounds(12);
    let rc_full1 = poseidon2_constants::load_rc_full1(12);
    let rc_partial = poseidon2_constants::load_rc_partial(12);
    let rc_full2 = poseidon2_constants::load_rc_full2(12);
} else {// T==16
    let pr = poseidon2_constants::amount_partial_rounds(16);
    let rc_full1 = poseidon2_constants::load_rc_full1(16);
    let rc_partial = poseidon2_constants::load_rc_partial(16);
    let rc_full2 = poseidon2_constants::load_rc_full2(16);
}
    // state[0] = ExternalMatMulT(in)
    let mut state = external_matmul_t::<T>(input);

    // First 4 full rounds
    for i in 0..4 {
        state = full_round::<T>(state, rc_full1[i]);
    }

    // pr partial rounds
    for i in 0..pr {
        state = partial_round::<T>(state, rc_partial[i]);
    }

    // Second 4 full rounds
    for i in 0..4 {
        state = full_round::<T>(state, rc_full2[i]);
    }

    state
}