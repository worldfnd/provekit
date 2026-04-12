use {
    super::engine::PooledBuffer,
    whir::hash::Hash,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct GpuField {
    pub(super) limbs: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NttStageParams {
    pub(super) row_len:        u32,
    pub(super) stride:         u32,
    pub(super) twiddle_offset: u32,
    pub(super) _pad0:          u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TransposeParams {
    pub(super) rows:           u32,
    pub(super) cols:           u32,
    pub(super) total_elements: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct EncodeFieldBytesParams {
    pub(super) rows: u32,
    pub(super) cols: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct HashManyParams {
    pub(super) size:  u32,
    pub(super) count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub(super) struct FieldMulParams {
    pub(super) count: u32,
}

pub(super) struct DeviceMatrix {
    pub(super) rows:   usize,
    pub(super) cols:   usize,
    pub(super) buffer: PooledBuffer,
}

#[derive(Clone)]
pub(super) struct DeviceRows {
    pub(super) rows:   usize,
    pub(super) cols:   usize,
    pub(super) buffer: PooledBuffer,
}

pub(super) struct DeviceMerkleWitness {
    pub(super) num_nodes: usize,
    pub(super) root:      Hash,
    pub(super) buffer:    PooledBuffer,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct EncodeShape {
    pub(super) row_count:       usize,
    pub(super) codeword_length: usize,
    pub(super) coset_size:      usize,
    pub(super) message_length:  usize,
    pub(super) mask_length:     usize,
    pub(super) num_cosets:      usize,
    pub(super) total_elements:  usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ReplicateCosetsParams {
    pub(super) row_len:           u32,
    pub(super) coset_size:        u32,
    pub(super) trailing_elements: u32,
}
