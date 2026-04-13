use {super::engine::PooledBuffer, whir::hash::Hash};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GpuField {
    pub limbs: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NttStageParams {
    pub row_len:        u32,
    pub stride:         u32,
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
#[allow(dead_code)]
pub struct FieldMulParams {
    pub count: u32,
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
