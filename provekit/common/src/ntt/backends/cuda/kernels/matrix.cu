// CUDA equivalent of metal/kernels/matrix.metal — same transpose.

extern "C" __global__ void transpose_matrix(
    const Fe *input,
    Fe *output,
    TransposeParams params
) {
    uint gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= params.total_elements) {
        return;
    }

    uint row = gid / params.cols;
    uint col = gid - row * params.cols;
    uint dst = col * params.rows + row;
    output[dst] = input[gid];
}
