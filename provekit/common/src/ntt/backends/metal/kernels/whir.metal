[[kernel]]
void vector_add_assign_scaled(
    device Fe *accumulator [[buffer(0)]],
    device const Fe *values [[buffer(1)]],
    constant Fe &scalar [[buffer(2)]],
    constant VectorLenParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.len) {
        return;
    }
    accumulator[gid] = add_mod(accumulator[gid], mont_mul(scalar, values[gid]));
}

[[kernel]]
void fold_vector_in_place(
    device Fe *values [[buffer(0)]],
    constant Fe &weight [[buffer(1)]],
    constant FoldParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.half_width) {
        return;
    }
    Fe low = values[gid];
    uint high_index = gid + params.half_width;
    Fe high = FE_ZERO;
    if (high_index < params.len) {
        high = values[high_index];
    }
    values[gid] = add_mod(low, mont_mul(sub_mod(high, low), weight));
}

[[kernel]]
void accumulate_univariate_evaluations(
    device Fe *accumulator [[buffer(0)]],
    device const Fe *points [[buffer(1)]],
    device const Fe *scalars [[buffer(2)]],
    constant UnivariateAccumParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.len) {
        return;
    }
    Fe value = accumulator[gid];
    for (uint i = 0; i < params.count; ++i) {
        value = add_mod(value, mont_mul(scalars[i], pow_u64(points[i], gid)));
    }
    accumulator[gid] = value;
}

[[kernel]]
void sumcheck_partials(
    device const Fe *a [[buffer(0)]],
    device const Fe *b [[buffer(1)]],
    device Fe *out_c0 [[buffer(2)]],
    device Fe *out_c2 [[buffer(3)]],
    constant SumcheckParams &params [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    uint start = gid * params.pairs_per_partial;
    if (start >= params.pair_count) {
        return;
    }
    uint end = min(start + params.pairs_per_partial, params.pair_count);
    Fe c0 = FE_ZERO;
    Fe c2 = FE_ZERO;
    for (uint pair = start; pair < end; ++pair) {
        Fe a0 = FE_ZERO;
        Fe b0 = FE_ZERO;
        if (pair < params.len) {
            a0 = a[pair];
            b0 = b[pair];
        }
        uint high = pair + params.half_width;
        Fe a1 = FE_ZERO;
        Fe b1 = FE_ZERO;
        if (high < params.len) {
            a1 = a[high];
            b1 = b[high];
        }
        c0 = add_mod(c0, mont_mul(a0, b0));
        c2 = add_mod(c2, mont_mul(sub_mod(a1, a0), sub_mod(b1, b0)));
    }
    out_c0[gid] = c0;
    out_c2[gid] = c2;
}

[[kernel]]
void reduce_field_pair_sum(
    device const Fe *input_c0 [[buffer(0)]],
    device const Fe *input_c2 [[buffer(1)]],
    device Fe *output_c0 [[buffer(2)]],
    device Fe *output_c2 [[buffer(3)]],
    constant ReduceParams &params [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    uint start = gid * params.values_per_chunk;
    if (start >= params.len) {
        return;
    }
    uint end = min(start + params.values_per_chunk, params.len);
    Fe sum_c0 = FE_ZERO;
    Fe sum_c2 = FE_ZERO;
    for (uint i = start; i < end; ++i) {
        sum_c0 = add_mod(sum_c0, input_c0[i]);
        sum_c2 = add_mod(sum_c2, input_c2[i]);
    }
    output_c0[gid] = sum_c0;
    output_c2[gid] = sum_c2;
}

[[kernel]]
void reduce_field_sum(
    device const Fe *input [[buffer(0)]],
    device Fe *output [[buffer(1)]],
    constant ReduceParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    uint start = gid * params.values_per_chunk;
    if (start >= params.len) {
        return;
    }
    uint end = min(start + params.values_per_chunk, params.len);
    Fe sum = FE_ZERO;
    for (uint i = start; i < end; ++i) {
        sum = add_mod(sum, input[i]);
    }
    output[gid] = sum;
}

[[kernel]]
void dot_product_partials(
    device const Fe *a [[buffer(0)]],
    device const Fe *b [[buffer(1)]],
    device Fe *output [[buffer(2)]],
    constant ReduceParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    uint start = gid * params.values_per_chunk;
    if (start >= params.len) {
        return;
    }
    uint end = min(start + params.values_per_chunk, params.len);
    Fe sum = FE_ZERO;
    for (uint i = start; i < end; ++i) {
        sum = add_mod(sum, mont_mul(a[i], b[i]));
    }
    output[gid] = sum;
}

[[kernel]]
void univariate_eval_partials(
    device const Fe *values [[buffer(0)]],
    device const Fe *points [[buffer(1)]],
    device Fe *partials [[buffer(2)]],
    constant UnivariateEvalParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    uint point_index = gid / params.partial_count;
    uint partial_index = gid - point_index * params.partial_count;
    if (point_index >= params.point_count) {
        return;
    }
    uint start = partial_index * params.values_per_chunk;
    if (start >= params.len) {
        return;
    }
    uint end = min(start + params.values_per_chunk, params.len);
    Fe point = points[point_index];
    Fe sum = FE_ZERO;
    for (uint i = start; i < end; ++i) {
        sum = add_mod(sum, mont_mul(values[i], pow_u64(point, i)));
    }
    partials[gid] = sum;
}

[[kernel]]
void eq_weights_init(
    device Fe *weights [[buffer(0)]],
    constant EqInitParams &params [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.gamma_count) {
        return;
    }
    weights[gid * params.stride] = FE_MONT_ONE;
}

[[kernel]]
void eq_weights_expand(
    device const Fe *input [[buffer(0)]],
    device Fe *output [[buffer(1)]],
    device const Fe *gamma_powers [[buffer(2)]],
    constant EqExpandParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    uint gamma_index = gid / params.stage_width;
    uint local = gid - gamma_index * params.stage_width;
    if (gamma_index >= params.gamma_count) {
        return;
    }
    uint base = gamma_index * params.stride;
    Fe value = input[base + local];
    Fe gamma_power = gamma_powers[gamma_index * params.power_stride + params.stage];
    Fe high = mont_mul(value, gamma_power);
    output[base + 2u * local] = sub_mod(value, high);
    output[base + 2u * local + 1u] = high;
}

[[kernel]]
void beq_accumulate_from_eq_half(
    device const Fe *eq_half [[buffer(0)]],
    device const Fe *tau_powers [[buffer(1)]],
    device Fe *beq [[buffer(2)]],
    constant Fe &masking_challenge [[buffer(3)]],
    constant BeqAccumParams &params [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.half_size) {
        return;
    }
    Fe accum = FE_ZERO;
    for (uint gamma_index = 0; gamma_index < params.gamma_count; ++gamma_index) {
        Fe eq = eq_half[gamma_index * params.half_size + gid];
        accum = add_mod(accum, mont_mul(tau_powers[gamma_index], eq));
    }
    Fe neg_rho = sub_mod(FE_ZERO, masking_challenge);
    Fe one_plus_rho = add_mod(FE_MONT_ONE, masking_challenge);
    beq[2u * gid] = mont_mul(one_plus_rho, accum);
    beq[2u * gid + 1u] = mont_mul(neg_rho, accum);
}

[[kernel]]
void gamma_eval_partials(
    device const Fe *eq_half [[buffer(0)]],
    device const Fe *packed_vectors [[buffer(1)]],
    device Fe *partials [[buffer(2)]],
    constant Fe &masking_challenge [[buffer(3)]],
    constant GammaEvalParams &params [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    uint partial_index = gid % params.partial_count;
    uint row = gid / params.partial_count;
    uint vector_index = row % params.vector_count;
    uint gamma_index = row / params.vector_count;
    if (gamma_index >= params.gamma_count) {
        return;
    }

    uint start = partial_index * params.values_per_partial;
    if (start >= params.half_size) {
        return;
    }
    uint end = min(start + params.values_per_partial, params.half_size);
    uint vector_offset = vector_index * params.weight_size;
    bool is_mask_vector = (vector_index % params.vectors_per_polynomial) == 0u;
    Fe neg_rho = sub_mod(FE_ZERO, masking_challenge);
    Fe one_plus_rho = add_mod(FE_MONT_ONE, masking_challenge);
    Fe sum = FE_ZERO;
    for (uint i = start; i < end; ++i) {
        Fe eq = eq_half[gamma_index * params.half_size + i];
        Fe value;
        if (is_mask_vector) {
            Fe even = packed_vectors[vector_offset + 2u * i];
            Fe odd = packed_vectors[vector_offset + 2u * i + 1u];
            value = add_mod(mont_mul(one_plus_rho, even), mont_mul(neg_rho, odd));
        } else {
            value = mont_mul(one_plus_rho, packed_vectors[vector_offset + 2u * i]);
        }
        sum = add_mod(sum, mont_mul(eq, value));
    }
    partials[gid] = sum;
}

[[kernel]]
void gamma_eval_reduce(
    device const Fe *partials [[buffer(0)]],
    device Fe *evals [[buffer(1)]],
    constant GammaReduceParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.row_count) {
        return;
    }
    uint offset = gid * params.partial_count;
    Fe sum = FE_ZERO;
    for (uint i = 0; i < params.partial_count; ++i) {
        sum = add_mod(sum, partials[offset + i]);
    }
    evals[gid] = sum;
}

[[kernel]]
void pack_device_vector_rows(
    device const Fe *vector [[buffer(0)]],
    device const Fe *masks [[buffer(1)]],
    device Fe *packed [[buffer(2)]],
    constant PackDeviceVectorParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    uint total = params.row_count * params.codeword_length;
    if (gid >= total) {
        return;
    }
    uint row = gid / params.codeword_length;
    uint col = gid - row * params.codeword_length;
    Fe value = FE_ZERO;
    if (col < params.message_length) {
        value = vector[row * params.message_length + col];
    } else {
        uint mask_col = col - params.message_length;
        if (mask_col < params.mask_length) {
            value = masks[mask_col * params.row_count + row];
        }
    }
    packed[gid] = value;
}
