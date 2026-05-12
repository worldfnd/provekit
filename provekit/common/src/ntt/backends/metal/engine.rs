use {
    super::{field::fr_to_gpu, logging::trace_event},
    ark_bn254::Fr,
    ark_ff::{FftField, Field},
    objc2::{
        rc::{autoreleasepool, Retained},
        runtime::ProtocolObject,
    },
    objc2_foundation::NSString,
    objc2_metal::{
        MTLBuffer, MTLCommandBuffer, MTLCommandQueue, MTLComputeCommandEncoder,
        MTLComputePipelineState, MTLCreateSystemDefaultDevice, MTLDevice, MTLLibrary,
        MTLResourceOptions, MTLSize,
    },
    std::{
        collections::HashMap,
        ffi::c_void,
        mem::size_of,
        ptr::{self, NonNull},
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

pub type Buffer = ProtocolObject<dyn MTLBuffer>;
pub type CommandBuffer = ProtocolObject<dyn MTLCommandBuffer>;
pub type CommandQueue = ProtocolObject<dyn MTLCommandQueue>;
pub type ComputeCommandEncoder = ProtocolObject<dyn MTLComputeCommandEncoder>;
pub type ComputePipelineState = ProtocolObject<dyn MTLComputePipelineState>;
pub type Device = ProtocolObject<dyn MTLDevice>;
pub type Library = ProtocolObject<dyn MTLLibrary>;

struct PooledBufferInner {
    runtime:      Arc<MetalRuntime>,
    bucket_bytes: usize,
    buffer:       Retained<Buffer>,
}

#[derive(Clone)]
pub struct PooledBuffer(Arc<PooledBufferInner>);

impl PooledBuffer {
    pub fn as_ref(&self) -> &Buffer {
        &self.0.buffer
    }
}

// SAFETY: Metal buffers are Objective-C resources intended to be referenced
// across command submission threads; buffer contents access remains explicitly
// synchronized by command buffer completion in this backend.
unsafe impl Send for PooledBufferInner {}
unsafe impl Sync for PooledBufferInner {}

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
            .recycle_buffer(self.bucket_bytes, self.buffer.clone());
    }
}

pub struct MetalRuntime {
    pub device:                    Retained<Device>,
    pub queue:                     Retained<CommandQueue>,
    pub bit_reverse_pipeline:      Retained<ComputePipelineState>,
    pub ntt_stage_pipeline:        Retained<ComputePipelineState>,
    pub replicate_cosets_pipeline: Retained<ComputePipelineState>,
    pub transpose_pipeline:        Retained<ComputePipelineState>,
    pub encode_bytes_pipeline:     Retained<ComputePipelineState>,
    pub sha256_pipeline:           Retained<ComputePipelineState>,
    roots_cache:                   Mutex<HashMap<usize, Arc<Retained<Buffer>>>>,
    buffer_pool:                   Mutex<HashMap<usize, Vec<Retained<Buffer>>>>,
}

// SAFETY: Metal device, queue, pipeline, and buffer handles are thread-safe
// Objective-C resources. Mutable Rust state is protected by mutexes.
unsafe impl Send for MetalRuntime {}
unsafe impl Sync for MetalRuntime {}

impl MetalRuntime {
    pub fn new() -> Result<Self, String> {
        autoreleasepool(|_| {
            let device = MTLCreateSystemDefaultDevice().ok_or_else(|| {
                "no Metal device found; sandboxed macOS processes may not expose Metal".to_string()
            })?;
            let shader_source = NSString::from_str(SHADER_SOURCE);
            let library = device
                .newLibraryWithSource_options_error(&shader_source, None)
                .map_err(|error| {
                    format!(
                        "failed to compile Metal shader: {}",
                        error.localizedDescription()
                    )
                })?;

            Ok(Self {
                queue: device
                    .newCommandQueue()
                    .ok_or_else(|| "Metal device did not create a command queue".to_string())?,
                bit_reverse_pipeline: Self::new_pipeline(
                    &device,
                    &library,
                    "bit_reverse_permute_rows_in_place",
                )?,
                ntt_stage_pipeline: Self::new_pipeline(
                    &device,
                    &library,
                    "radix2_ntt_stage_rows_in_place",
                )?,
                replicate_cosets_pipeline: Self::new_pipeline(
                    &device,
                    &library,
                    "replicate_first_coset",
                )?,
                transpose_pipeline: Self::new_pipeline(&device, &library, "transpose_matrix")?,
                encode_bytes_pipeline: Self::new_pipeline(
                    &device,
                    &library,
                    "encode_field_rows_le",
                )?,
                sha256_pipeline: Self::new_pipeline(&device, &library, "sha256_many")?,
                device,
                roots_cache: Mutex::new(HashMap::new()),
                buffer_pool: Mutex::new(HashMap::new()),
            })
        })
    }

    pub fn buffer_with_data<T: Copy>(&self, values: &[T]) -> Retained<Buffer> {
        if values.is_empty() {
            return self
                .device
                .newBufferWithLength_options(0, MTLResourceOptions::StorageModeShared)
                .expect("Metal device must create an empty input buffer");
        }

        let pointer = NonNull::new(values.as_ptr() as *mut c_void)
            .expect("non-empty slice pointer is not null");
        unsafe {
            self.device
                .newBufferWithBytes_length_options(
                    pointer,
                    std::mem::size_of_val(values),
                    MTLResourceOptions::StorageModeShared,
                )
                .expect("Metal device must create an input buffer")
        }
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
        let ptr = buffer.contents().as_ptr().cast::<T>();
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    pub fn buffer_slice_mut<'a, T>(&self, buffer: &'a Buffer, len: usize) -> &'a mut [T] {
        let ptr = buffer.contents().as_ptr().cast::<T>();
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }

    pub fn zero_buffer<T>(&self, buffer: &Buffer, len: usize) {
        if len == 0 {
            return;
        }
        unsafe {
            ptr::write_bytes(buffer.contents().as_ptr(), 0, len * size_of::<T>());
        }
    }

    pub fn threads_per_threadgroup(
        &self,
        pipeline: &ComputePipelineState,
        work_items: usize,
    ) -> MTLSize {
        let width = pipeline
            .threadExecutionWidth()
            .min(pipeline.maxTotalThreadsPerThreadgroup())
            .min(work_items)
            .max(1);
        MTLSize {
            width,
            height: 1,
            depth: 1,
        }
    }

    pub fn roots_buffer(&self, codeword_length: usize) -> Result<Arc<Retained<Buffer>>, String> {
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

    fn take_buffer(&self, bucket_bytes: usize) -> Retained<Buffer> {
        if bucket_bytes == 0 {
            return self
                .device
                .newBufferWithLength_options(0, MTLResourceOptions::StorageModeShared)
                .expect("Metal device must create an empty pooled buffer");
        }

        let mut pool = self.buffer_pool.lock().unwrap();
        if let Some(buffer) = pool.get_mut(&bucket_bytes).and_then(Vec::pop) {
            return buffer;
        }
        drop(pool);

        self.device
            .newBufferWithLength_options(bucket_bytes, MTLResourceOptions::StorageModeShared)
            .expect("Metal device must create a pooled buffer")
    }

    fn recycle_buffer(&self, bucket_bytes: usize, buffer: Retained<Buffer>) {
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
    ) -> Result<Retained<ComputePipelineState>, String> {
        let function_name = NSString::from_str(function_name);
        let function = library
            .newFunctionWithName(&function_name)
            .ok_or_else(|| format!("Metal shader function `{function_name}` not found"))?;
        device
            .newComputePipelineStateWithFunction_error(&function)
            .map_err(|error| {
                format!(
                    "failed to create Metal compute pipeline `{function_name}`: {}",
                    error.localizedDescription()
                )
            })
    }
}

pub fn new_command_buffer(queue: &CommandQueue) -> Result<Retained<CommandBuffer>, String> {
    queue
        .commandBuffer()
        .ok_or_else(|| "Metal command queue did not create a command buffer".to_string())
}

pub fn new_compute_encoder(
    command_buffer: &CommandBuffer,
) -> Result<Retained<ComputeCommandEncoder>, String> {
    command_buffer.computeCommandEncoder().ok_or_else(|| {
        "Metal command buffer did not create a compute command encoder".to_string()
    })
}

pub fn set_buffer(encoder: &ComputeCommandEncoder, index: usize, buffer: &Buffer, offset: usize) {
    unsafe {
        encoder.setBuffer_offset_atIndex(Some(buffer), offset, index);
    }
}

pub fn set_bytes<T>(encoder: &ComputeCommandEncoder, index: usize, value: &T) {
    unsafe {
        encoder.setBytes_length_atIndex(
            NonNull::from(value).cast::<c_void>(),
            size_of::<T>(),
            index,
        );
    }
}

pub fn check_command_buffer(command_buffer: &CommandBuffer) -> Result<(), String> {
    if let Some(error) = command_buffer.error() {
        Err(format!(
            "Metal command buffer failed: {}",
            error.localizedDescription()
        ))
    } else {
        Ok(())
    }
}

fn bucket_bytes(bytes: usize) -> usize {
    if bytes == 0 {
        0
    } else {
        bytes.next_power_of_two()
    }
}
