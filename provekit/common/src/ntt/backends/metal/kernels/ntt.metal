[[kernel]]
void bit_reverse_permute_rows_in_place(
    device Fe *values [[buffer(0)]],
    constant BitReverseParams &config [[buffer(1)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= config.total_elements || config.row_len <= 1u) {
        return;
    }

    uint row = index / config.row_len;
    uint within = index - row * config.row_len;
    uint reversed = reverse_bits_width(within, config.log_n);
    if (reversed <= within) {
        return;
    }

    uint row_base = row * config.row_len;
    uint mate = row_base + reversed;
    uint current = row_base + within;
    Fe tmp = values[current];
    values[current] = values[mate];
    values[mate] = tmp;
}

[[kernel]]
void radix2_ntt_stage_rows_in_place(
    device Fe *values [[buffer(0)]],
    device const Fe *twiddles [[buffer(1)]],
    constant StageConfig &config [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    uint butterflies_per_row = config.row_len >> 1u;
    uint row = index / butterflies_per_row;
    uint local = index - row * butterflies_per_row;
    uint half_m = config.half_m;
    uint pair_in_group = local % half_m;
    uint group = local / half_m;
    uint row_base = row * config.row_len;
    uint base = row_base + group * (half_m << 1u) + pair_in_group;
    uint mate = base + half_m;

    Fe even = values[base];
    Fe odd = values[mate];
    Fe twiddle = twiddles[config.twiddle_offset + pair_in_group];
    Fe t = mont_mul(twiddle, odd);

    values[base] = add_mod(even, t);
    values[mate] = sub_mod(even, t);
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

