[[kernel]]
void transpose_matrix(
    device const Fe *input [[buffer(0)]],
    device Fe *output [[buffer(1)]],
    constant TransposeParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.total_elements) {
        return;
    }

    uint row = gid / params.cols;
    uint col = gid - row * params.cols;
    uint dst = col * params.rows + row;
    output[dst] = input[gid];
}

[[kernel]]
void encode_field_rows_le(
    device const Fe *input [[buffer(0)]],
    device uchar *output [[buffer(1)]],
    constant FieldBytesParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    uint total_elements = params.rows * params.cols;
    if (gid >= total_elements) {
        return;
    }

    uint row = gid / params.cols;
    uint col = gid - row * params.cols;
    uint row_bits = 31u - clz(params.rows);
    uint src_row = reverse_bits_width(row, row_bits);
    Fe canonical = from_mont(input[src_row * params.cols + col]);
    uint byte_offset = gid * 32u;
    for (uint limb = 0; limb < 4; ++limb) {
        ulong value = canonical.limbs[limb];
        for (uint byte = 0; byte < 8; ++byte) {
            output[byte_offset + limb * 8u + byte] = uchar((value >> (byte * 8u)) & 0xfful);
        }
    }
}

[[kernel]]
void gather_bit_reversed_rows(
    device const Fe *input [[buffer(0)]],
    device const uint *indices [[buffer(1)]],
    device Fe *output [[buffer(2)]],
    constant GatherRowsParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    uint total_elements = params.count * params.cols;
    if (gid >= total_elements) {
        return;
    }

    uint out_row = gid / params.cols;
    uint col = gid - out_row * params.cols;
    uint row = indices[out_row];
    if (row >= params.rows) {
        return;
    }

    uint row_bits = 31u - clz(params.rows);
    uint src_row = row_bits == 0u ? row : reverse_bits_width(row, row_bits);
    output[gid] = input[src_row * params.cols + col];
}

[[kernel]]
void gather_hashes(
    device const uchar *input [[buffer(0)]],
    device const uint *indices [[buffer(1)]],
    device uchar *output [[buffer(2)]],
    constant GatherHashesParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    constexpr uint HASH_BYTES = 32u;
    uint total_bytes = params.count * HASH_BYTES;
    if (gid >= total_bytes) {
        return;
    }

    uint out_index = gid / HASH_BYTES;
    uint byte_index = gid - out_index * HASH_BYTES;
    uint node_index = indices[out_index];
    if (node_index >= params.num_nodes) {
        return;
    }

    output[gid] = input[node_index * HASH_BYTES + byte_index];
}
