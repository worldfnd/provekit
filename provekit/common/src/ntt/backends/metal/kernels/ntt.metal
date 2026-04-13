[[kernel]]
void stockham_ntt_stage(
    device const Fe *input [[buffer(0)]],
    device Fe *output [[buffer(1)]],
    device const Fe *twiddles [[buffer(2)]],
    constant StageConfig &config [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    uint butterflies_per_row = config.row_len >> 1u;
    uint row = index / butterflies_per_row;
    uint local = index - row * butterflies_per_row;
    uint stride = config.stride;
    uint j = local % stride;
    uint k = local / stride;

    uint row_base = row * config.row_len;
    uint base = row_base + k * (stride << 1u) + j;
    uint mate = base + stride;

    Fe even = input[base];
    Fe odd = input[mate];
    Fe twiddle = twiddles[config.twiddle_offset + k];
    Fe t = mont_mul(twiddle, odd);
    uint out_base = row_base + k * stride + j;

    output[out_base] = add_mod(even, t);
    output[out_base + butterflies_per_row] = sub_mod(even, t);
}

[[kernel]]
void replicate_first_coset(
    device Fe *buffer [[buffer(0)]],
    constant ReplicateCosetsParams &params [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.trailing_elements) {
        return;
    }

    uint repeats_per_row = params.row_len - params.coset_size;
    uint row = gid / repeats_per_row;
    uint within = gid - row * repeats_per_row;
    uint dst = row * params.row_len + params.coset_size + within;
    uint src = row * params.row_len + (within % params.coset_size);
    buffer[dst] = buffer[src];
}

