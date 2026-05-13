use {super::engine::PooledBuffer, whir::hash::Hash};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GpuField {
    pub limbs: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BitReverseParams {
    pub row_len:        u32,
    pub log_n:          u32,
    pub total_elements: u32,
    pub _pad0:          u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NttStageParams {
    pub row_len:        u32,
    pub half_m:         u32,
    pub twiddle_offset: u32,
    pub _pad0:          u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TransposeParams {
    pub rows:           u32,
    pub cols:           u32,
    pub total_elements: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EncodeFieldBytesParams {
    pub rows: u32,
    pub cols: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HashManyParams {
    pub size:  u32,
    pub count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GatherRowsParams {
    pub rows:  u32,
    pub cols:  u32,
    pub count: u32,
    pub _pad0: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GatherHashesParams {
    pub num_nodes: u32,
    pub count:     u32,
    pub _pad0:     u32,
    pub _pad1:     u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VectorLenParams {
    pub len:   u32,
    pub _pad0: u32,
    pub _pad1: u32,
    pub _pad2: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FoldParams {
    pub len:        u32,
    pub half_width: u32,
    pub _pad0:      u32,
    pub _pad1:      u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SumcheckParams {
    pub len:               u32,
    pub half_width:        u32,
    pub pair_count:        u32,
    pub pairs_per_partial: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReduceParams {
    pub len:              u32,
    pub values_per_chunk: u32,
    pub _pad0:            u32,
    pub _pad1:            u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UnivariateAccumParams {
    pub len:   u32,
    pub count: u32,
    pub _pad0: u32,
    pub _pad1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UnivariateEvalParams {
    pub len:              u32,
    pub point_count:      u32,
    pub values_per_chunk: u32,
    pub partial_count:    u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EqInitParams {
    pub gamma_count: u32,
    pub stride:      u32,
    pub _pad0:       u32,
    pub _pad1:       u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EqExpandParams {
    pub gamma_count:  u32,
    pub stride:       u32,
    pub stage_width:  u32,
    pub stage:        u32,
    pub power_stride: u32,
    pub _pad0:        u32,
    pub _pad1:        u32,
    pub _pad2:        u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BeqAccumParams {
    pub half_size:   u32,
    pub gamma_count: u32,
    pub _pad0:       u32,
    pub _pad1:       u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GammaEvalParams {
    pub half_size:              u32,
    pub weight_size:            u32,
    pub vector_count:           u32,
    pub vectors_per_polynomial: u32,
    pub gamma_count:            u32,
    pub partial_count:          u32,
    pub values_per_partial:     u32,
    pub _pad0:                  u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GammaReduceParams {
    pub row_count:     u32,
    pub partial_count: u32,
    pub _pad0:         u32,
    pub _pad1:         u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PackDeviceVectorParams {
    pub row_count:       u32,
    pub codeword_length: u32,
    pub message_length:  u32,
    pub mask_length:     u32,
}

pub struct DeviceMatrix {
    pub rows:   usize,
    pub cols:   usize,
    pub buffer: PooledBuffer,
}

#[derive(Clone)]
pub struct DeviceRows {
    pub rows:   usize,
    pub cols:   usize,
    pub buffer: PooledBuffer,
}

pub struct DeviceMerkleWitness {
    pub num_nodes: usize,
    pub root:      Hash,
    pub buffer:    PooledBuffer,
}

#[derive(Clone, Copy, Debug)]
pub struct EncodeShape {
    pub row_count:       usize,
    pub codeword_length: usize,
    pub coset_size:      usize,
    pub message_length:  usize,
    pub mask_length:     usize,
    pub num_cosets:      usize,
    pub total_elements:  usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReplicateCosetsParams {
    pub row_len:           u32,
    pub coset_size:        u32,
    pub trailing_elements: u32,
}
