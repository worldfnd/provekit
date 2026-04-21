use {
    super::{field::fr_to_gpu, logging::trace_event},
    ark_bn254::Fr,
    ark_ff::{FftField, Field},
    metal::{
        objc::rc::autoreleasepool, Buffer, CommandQueue, CompileOptions, ComputePipelineState,
        Device, Library, MTLResourceOptions, MTLSize, NSUInteger,
    },
    std::{
        collections::HashMap,
        ffi::c_void,
        mem::size_of,
        ptr,
        sync::{Arc, Mutex},
    },
};

const SHADER_SOURCE: &str = concat!(
    include_str!("kernels/common.metal"),
    "\n",
    include_str!("kernels/field.metal"),
    "\n",
    include_str!("kernels/ntt.metal"),
    "\n",
    include_str!("kernels/matrix.metal"),
    "\n",
    include_str!("kernels/sha256.metal"),
    "\n",
);

struct PooledBufferInner {
    runtime:      Arc<MetalRuntime>,
    bucket_bytes: usize,
    buffer:       Buffer,
}

#[derive(Clone)]
pub struct PooledBuffer(Arc<PooledBufferInner>);

impl PooledBuffer {
    pub fn as_ref(&self) -> &Buffer {
        &self.0.buffer
    }
}

impl std::fmt::Debug for PooledBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuffer")
            .field("length", &self.0.buffer.length())
            .finish()
    }
}

impl std::ops::Deref for PooledBuffer {
    type Target = Buffer;

    fn deref(&self) -> &Self::Target {
        &self.0.buffer
    }
}

impl AsRef<Buffer> for PooledBuffer {
    fn as_ref(&self) -> &Buffer {
        &self.0.buffer
    }
}

impl Drop for PooledBufferInner {
    fn drop(&mut self) {
        self.runtime
            .recycle_buffer(self.bucket_bytes, self.buffer.to_owned());
    }
}

pub struct MetalRuntime {
    pub device:                    Device,
    pub queue:                     CommandQueue,
    pub bit_reverse_pipeline:      ComputePipelineState,
    pub ntt_stage_pipeline:        ComputePipelineState,
    pub replicate_cosets_pipeline: ComputePipelineState,
    pub transpose_pipeline:        ComputePipelineState,
    pub encode_bytes_pipeline:     ComputePipelineState,
    pub sha256_pipeline:           ComputePipelineState,
    roots_cache:                   Mutex<HashMap<usize, Arc<Buffer>>>,
    buffer_pool:                   Mutex<HashMap<usize, Vec<Buffer>>>,
}

impl MetalRuntime {
    pub fn new() -> Result<Self, String> {
        autoreleasepool(|| {
            let device = Device::system_default()
                .or_else(|| Device::all().into_iter().next())
                .ok_or_else(|| {
                    "no Metal device found; sandboxed macOS processes may not expose Metal"
                        .to_string()
                })?;
            let options = CompileOptions::new();
            let library = device.new_library_with_source(SHADER_SOURCE, &options)?;

            Ok(Self {
                device:                    device.to_owned(),
                queue:                     device.new_command_queue(),
                bit_reverse_pipeline:      Self::new_pipeline(
                    &device,
                    &library,
                    "bit_reverse_permute_rows_in_place",
                )?,
                ntt_stage_pipeline:        Self::new_pipeline(
                    &device,
                    &library,
                    "radix2_ntt_stage_rows_in_place",
                )?,
                replicate_cosets_pipeline: Self::new_pipeline(
                    &device,
                    &library,
                    "replicate_first_coset",
                )?,
                transpose_pipeline:        Self::new_pipeline(
                    &device,
                    &library,
                    "transpose_matrix",
                )?,
                encode_bytes_pipeline:     Self::new_pipeline(
                    &device,
                    &library,
                    "encode_field_rows_le",
                )?,
                sha256_pipeline:           Self::new_pipeline(&device, &library, "sha256_many")?,
                roots_cache:               Mutex::new(HashMap::new()),
                buffer_pool:               Mutex::new(HashMap::new()),
            })
        })
    }

    pub fn buffer_with_data<T: Copy>(&self, values: &[T]) -> Buffer {
        self.device.new_buffer_with_data(
            values.as_ptr().cast::<c_void>(),
            std::mem::size_of_val(values) as NSUInteger,
            MTLResourceOptions::StorageModeShared,
        )
    }

    pub fn pooled_buffer<T>(self: &Arc<Self>, len: usize) -> PooledBuffer {
        self.pooled_bytes(len * size_of::<T>())
    }

    pub fn pooled_bytes(self: &Arc<Self>, len: usize) -> PooledBuffer {
        let bucket_bytes = bucket_bytes(len);
        let buffer = self.take_buffer(bucket_bytes);
        PooledBuffer(Arc::new(PooledBufferInner {
            runtime: Arc::clone(self),
            bucket_bytes,
            buffer,
        }))
    }

    pub fn buffer_slice<'a, T>(&self, buffer: &'a Buffer, len: usize) -> &'a [T] {
        let ptr = buffer.contents().cast::<T>();
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    pub fn buffer_slice_mut<'a, T>(&self, buffer: &'a Buffer, len: usize) -> &'a mut [T] {
        let ptr = buffer.contents().cast::<T>();
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }

    pub fn zero_buffer<T>(&self, buffer: &Buffer, len: usize) {
        if len == 0 {
            return;
        }
        unsafe {
            ptr::write_bytes(buffer.contents(), 0, len * size_of::<T>());
        }
    }

    pub fn threads_per_threadgroup(
        &self,
        pipeline: &ComputePipelineState,
        work_items: usize,
    ) -> MTLSize {
        let width = pipeline
            .thread_execution_width()
            .min(pipeline.max_total_threads_per_threadgroup())
            .min(work_items as u64)
            .max(1);
        MTLSize {
            width,
            height: 1,
            depth: 1,
        }
    }

    pub fn roots_buffer(&self, codeword_length: usize) -> Result<Arc<Buffer>, String> {
        let mut cache = self.roots_cache.lock().unwrap();
        if let Some(buffer) = cache.get(&codeword_length) {
            trace_event(format_args!(
                "roots cache hit codeword_length={codeword_length}"
            ));
            return Ok(Arc::clone(buffer));
        }

        let root = Fr::get_root_of_unity(codeword_length as u64).unwrap();
        let stage_count = codeword_length.trailing_zeros() as usize;
        let mut roots = Vec::with_capacity(codeword_length.saturating_sub(1));
        for stage in 0..stage_count {
            let stage_size = 1usize << (stage + 1);
            let half_stage = stage_size >> 1;
            let stage_root = root.pow([(codeword_length / stage_size) as u64]);
            let mut current = Fr::ONE;
            for _ in 0..half_stage {
                roots.push(fr_to_gpu(current));
                current *= stage_root;
            }
        }

        let buffer = Arc::new(self.buffer_with_data(&roots));
        cache.insert(codeword_length, Arc::clone(&buffer));
        trace_event(format_args!(
            "roots cache miss codeword_length={codeword_length}"
        ));
        Ok(buffer)
    }

    fn take_buffer(&self, bucket_bytes: usize) -> Buffer {
        if bucket_bytes == 0 {
            return self
                .device
                .new_buffer(0, MTLResourceOptions::StorageModeShared);
        }

        let mut pool = self.buffer_pool.lock().unwrap();
        if let Some(buffer) = pool.get_mut(&bucket_bytes).and_then(Vec::pop) {
            return buffer;
        }
        drop(pool);

        self.device
            .new_buffer(bucket_bytes as u64, MTLResourceOptions::StorageModeShared)
    }

    fn recycle_buffer(&self, bucket_bytes: usize, buffer: Buffer) {
        if bucket_bytes == 0 {
            return;
        }

        let mut pool = self.buffer_pool.lock().unwrap();
        pool.entry(bucket_bytes).or_default().push(buffer);
    }

    fn new_pipeline(
        device: &Device,
        library: &Library,
        function_name: &str,
    ) -> Result<ComputePipelineState, String> {
        library
            .get_function(function_name, None)
            .map_err(|err| err.to_string())
            .and_then(|function| device.new_compute_pipeline_state_with_function(&function))
    }
}

fn bucket_bytes(bytes: usize) -> usize {
    if bytes == 0 {
        0
    } else {
        bytes.next_power_of_two()
    }
}
