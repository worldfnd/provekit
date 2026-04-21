use {super::engine::PooledBuffer, whir::hash::Hash};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GpuField {
    pub limbs: [u64; 4],
}

// SAFETY: GpuField is repr(C) and contains only POD limbs.
unsafe impl cudarc::driver::DeviceRepr for GpuField {}
// SAFETY: GpuField has no padding; an all-zero bit pattern represents the
// field element 0 (same in standard and Montgomery form).
unsafe impl cudarc::driver::ValidAsZeroBits for GpuField {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BitReverseParams {
    pub row_len:        u32,
    pub log_n:          u32,
    pub total_elements: u32,
    pub _pad0:          u32,
}
// SAFETY: POD repr(C) struct.
unsafe impl cudarc::driver::DeviceRepr for BitReverseParams {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NttStageParams {
    pub row_len:        u32,
    pub half_m:         u32,
    pub twiddle_offset: u32,
    pub _pad0:          u32,
}
// SAFETY: POD repr(C) struct.
unsafe impl cudarc::driver::DeviceRepr for NttStageParams {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TransposeParams {
    pub rows:           u32,
    pub cols:           u32,
    pub total_elements: u32,
}
// SAFETY: POD repr(C) struct.
unsafe impl cudarc::driver::DeviceRepr for TransposeParams {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EncodeFieldBytesParams {
    pub rows: u32,
    pub cols: u32,
}
// SAFETY: POD repr(C) struct.
unsafe impl cudarc::driver::DeviceRepr for EncodeFieldBytesParams {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HashManyParams {
    pub size:  u32,
    pub count: u32,
}
// SAFETY: POD repr(C) struct.
unsafe impl cudarc::driver::DeviceRepr for HashManyParams {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReplicateCosetsParams {
    pub row_len:           u32,
    pub coset_size:        u32,
    pub trailing_elements: u32,
}
// SAFETY: POD repr(C) struct.
unsafe impl cudarc::driver::DeviceRepr for ReplicateCosetsParams {}

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
