use {
    super::{field::fr_to_gpu, logging::trace_event, types::GpuField},
    ark_bn254::Fr,
    ark_ff::{FftField, Field},
    cudarc::{
        driver::{
            result, sys, CudaContext, CudaFunction, CudaModule, CudaSlice, CudaStream, DevicePtr,
            DriverError, LaunchConfig,
        },
        nvrtc::{compile_ptx_with_opts, CompileOptions, Ptx},
    },
    std::{
        collections::{hash_map::DefaultHasher, HashMap},
        fs,
        hash::{Hash as _, Hasher},
        mem::{size_of, ManuallyDrop},
        path::PathBuf,
        sync::{Arc, Mutex},
    },
};

const CUDA_SOURCE: &str = concat!(
    "// common.cuh\n",
    include_str!("kernels/common.cuh"),
    "\n// field.cuh\n",
    include_str!("kernels/field.cuh"),
    "\n// ntt.cu\n",
    include_str!("kernels/ntt.cu"),
    "\n// matrix.cu\n",
    include_str!("kernels/matrix.cu"),
    "\n// sha256.cu\n",
    include_str!("kernels/sha256.cu"),
    "\n",
);

// ---------------------------------------------------------------------------
// PooledBuffer: an Arc-wrapped CudaSlice<u8> that returns to the runtime's
// pool on drop. We bucket allocations by power-of-two byte size, mirroring
// the Metal backend's PooledBuffer. All sizes are tracked in bytes so a
// single pool can serve GpuField, Hash, and raw-byte buffers.
//
// Buffers are exposed as `&CudaSlice<u8>`. cudarc's `launch_builder.arg(&s)`
// accepts an immutable reference even for kernels that mutate the slice (it
// only forwards the raw device pointer to the kernel), so we never need a
// `&mut CudaSlice` and can keep the buffer behind `Arc`.
// ---------------------------------------------------------------------------

struct PooledBufferInner {
    runtime:      Arc<CudaRuntime>,
    bucket_bytes: usize,
    /// `ManuallyDrop` so we can take the slice out in `Drop` and recycle it.
    buffer:       ManuallyDrop<CudaSlice<u8>>,
}

#[derive(Clone)]
pub struct PooledBuffer(Arc<PooledBufferInner>);

impl PooledBuffer {
    pub fn slice(&self) -> &CudaSlice<u8> {
        &self.0.buffer
    }

    pub fn bucket_bytes(&self) -> usize {
        self.0.bucket_bytes
    }
}

impl std::fmt::Debug for PooledBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuffer")
            .field("bucket_bytes", &self.0.bucket_bytes)
            .finish()
    }
}

impl Drop for PooledBufferInner {
    fn drop(&mut self) {
        // SAFETY: `buffer` is initialised on construction and dropped only here.
        let buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
        self.runtime.recycle_buffer(self.bucket_bytes, buffer);
    }
}

// ---------------------------------------------------------------------------
// CudaRuntime: long-lived context, default stream, kernel handles, NTT root
// table cache, and buffer pool. Initialised once per process via
// `CudaBn254Ntt::new`.
// ---------------------------------------------------------------------------

pub struct CudaRuntime {
    // Held to keep the context alive (the stream and modules transitively
    // depend on it); we don't call methods on it directly.
    #[allow(dead_code)]
    pub context:                   Arc<CudaContext>,
    pub stream:                    Arc<CudaStream>,
    pub device_name:               String,
    pub compute_capability:        (i32, i32),
    pub max_block_size:            u32,
    #[allow(dead_code)]
    module:                        Arc<CudaModule>,
    pub bit_reverse_function:      CudaFunction,
    pub ntt_stage_function:        CudaFunction,
    pub replicate_cosets_function: CudaFunction,
    pub transpose_function:        CudaFunction,
    pub encode_bytes_function:     CudaFunction,
    pub sha256_function:           CudaFunction,
    roots_cache:                   Mutex<HashMap<usize, Arc<CudaSlice<GpuField>>>>,
    buffer_pool:                   Mutex<HashMap<usize, Vec<CudaSlice<u8>>>>,
}

impl CudaRuntime {
    pub fn new() -> Result<Self, String> {
        let context = CudaContext::new(0).map_err(driver_err)?;
        let stream = context.default_stream();
        let device_name = context.name().map_err(driver_err)?;
        let (cc_major, cc_minor) = context.compute_capability().map_err(driver_err)?;

        let arch = arch_for_compute_capability(cc_major, cc_minor);
        let ptx = compile_or_load_ptx(CUDA_SOURCE, arch)?;
        let module = context.load_module(ptx).map_err(driver_err)?;

        let bit_reverse_function = module
            .load_function("bit_reverse_permute_rows_in_place")
            .map_err(driver_err)?;
        let ntt_stage_function = module
            .load_function("radix2_ntt_stage_rows_in_place")
            .map_err(driver_err)?;
        let replicate_cosets_function = module
            .load_function("replicate_first_coset")
            .map_err(driver_err)?;
        let transpose_function = module
            .load_function("transpose_matrix")
            .map_err(driver_err)?;
        let encode_bytes_function = module
            .load_function("encode_field_rows_le")
            .map_err(driver_err)?;
        let sha256_function = module
            .load_function("sha256_many")
            .map_err(driver_err)?;

        Ok(Self {
            context,
            stream,
            device_name,
            compute_capability: (cc_major, cc_minor),
            max_block_size: 256,
            module,
            bit_reverse_function,
            ntt_stage_function,
            replicate_cosets_function,
            transpose_function,
            encode_bytes_function,
            sha256_function,
            roots_cache: Mutex::new(HashMap::new()),
            buffer_pool: Mutex::new(HashMap::new()),
        })
    }

    // ----- buffer pool -----------------------------------------------------

    pub fn pooled_buffer<T>(self: &Arc<Self>, len: usize) -> PooledBuffer {
        self.pooled_bytes(len * size_of::<T>())
    }

    pub fn pooled_bytes(self: &Arc<Self>, bytes: usize) -> PooledBuffer {
        let bucket_bytes = bucket_bytes(bytes);
        let buffer = self.take_buffer(bucket_bytes);
        PooledBuffer(Arc::new(PooledBufferInner {
            runtime: Arc::clone(self),
            bucket_bytes,
            buffer: ManuallyDrop::new(buffer),
        }))
    }

    fn take_buffer(&self, bucket_bytes: usize) -> CudaSlice<u8> {
        // cudarc disallows zero-byte allocs; back empty buffers with a
        // single byte instead. Callers never read it.
        let alloc_bytes = bucket_bytes.max(1);
        if let Some(buffer) = self
            .buffer_pool
            .lock()
            .unwrap()
            .get_mut(&bucket_bytes)
            .and_then(Vec::pop)
        {
            return buffer;
        }
        // SAFETY: Caller is responsible for fully overwriting any region
        // they later read from. `gpu_encode` zeroes the working buffer
        // before any read; the SHA path memsets the tree buffer first;
        // downloads only read regions explicitly written by a prior kernel.
        unsafe {
            self.stream
                .alloc::<u8>(alloc_bytes)
                .expect("CUDA pooled-buffer alloc")
        }
    }

    fn recycle_buffer(&self, bucket_bytes: usize, buffer: CudaSlice<u8>) {
        if bucket_bytes == 0 {
            return;
        }
        self.buffer_pool
            .lock()
            .unwrap()
            .entry(bucket_bytes)
            .or_default()
            .push(buffer);
    }

    // ----- raw byte-level memset / memcpy ---------------------------------

    /// Synchronously enqueue a byte memset of `bytes` bytes starting at
    /// `offset_bytes` inside `dst`.
    pub fn memset_zeros(
        &self,
        dst: &PooledBuffer,
        offset_bytes: usize,
        bytes: usize,
    ) -> Result<(), String> {
        if bytes == 0 {
            return Ok(());
        }
        debug_assert!(offset_bytes + bytes <= dst.bucket_bytes());
        let (ptr, _hold) = dst.slice().device_ptr(&self.stream);
        // SAFETY: `ptr + offset_bytes` is in-bounds of the alloc; `bytes`
        // does not exceed the bucket size; the stream is the alloc's stream.
        unsafe {
            result::memset_d8_async(
                ptr + offset_bytes as sys::CUdeviceptr,
                0,
                bytes,
                self.stream.cu_stream(),
            )
        }
        .map_err(driver_err)
    }

    /// Upload `host` into `dst` starting at `dst_offset_bytes`. `T` must be
    /// layout-equivalent to `GpuField` (4×u64 Montgomery limbs); this is how
    /// we support `&[Fr]` directly without a host pack pass.
    ///
    /// # Safety
    ///
    /// `T` must have identical size/alignment/layout to `GpuField`, and
    /// `dst_offset_bytes + size_of::<T>() * host.len()` must be `<= dst.bucket_bytes()`.
    pub unsafe fn upload_into<T: Copy>(
        &self,
        host: &[T],
        dst: &PooledBuffer,
        dst_offset_bytes: usize,
    ) -> Result<(), String> {
        if host.is_empty() {
            return Ok(());
        }
        debug_assert_eq!(size_of::<T>(), size_of::<GpuField>());
        let bytes = std::mem::size_of_val(host);
        debug_assert!(dst_offset_bytes + bytes <= dst.bucket_bytes());
        // SAFETY: caller guarantees layout equivalence.
        let host_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(host.as_ptr().cast::<u8>(), bytes) };
        let (ptr, _hold) = dst.slice().device_ptr(&self.stream);
        // SAFETY: device pointer + offset is in-bounds; lifetime of `host`
        // extends past the synchronisation we perform later (caller is
        // expected to synchronise the stream before reusing the buffer).
        unsafe {
            result::memcpy_htod_async(
                ptr + dst_offset_bytes as sys::CUdeviceptr,
                host_bytes,
                self.stream.cu_stream(),
            )
        }
        .map_err(driver_err)
    }

    /// Download `dst.len()` `T` elements from `src` (starting at
    /// `src_offset_bytes`) into `dst`. Synchronously: blocks the host until
    /// the copy is complete. For batched downloads, prefer pairing
    /// [`download_into_async`] calls with a single trailing
    /// [`synchronize`].
    ///
    /// # Safety
    ///
    /// Same as [`upload_into`].
    pub unsafe fn download_into<T: Copy>(
        &self,
        src: &PooledBuffer,
        src_offset_bytes: usize,
        dst: &mut [T],
    ) -> Result<(), String> {
        // SAFETY: forwarded.
        unsafe { self.download_into_async::<T>(src, src_offset_bytes, dst) }?;
        self.synchronize()
    }

    /// Asynchronous variant of [`download_into`]: queues the device-to-host
    /// copy on the stream but does NOT synchronise. Caller MUST synchronise
    /// (or otherwise wait on the stream) before reading from `dst`.
    ///
    /// # Safety
    ///
    /// Same as [`upload_into`], plus the caller must keep `dst` alive and
    /// not move it until the stream synchronises.
    pub unsafe fn download_into_async<T: Copy>(
        &self,
        src: &PooledBuffer,
        src_offset_bytes: usize,
        dst: &mut [T],
    ) -> Result<(), String> {
        if dst.is_empty() {
            return Ok(());
        }
        debug_assert_eq!(size_of::<T>(), size_of::<GpuField>());
        let bytes = std::mem::size_of_val(dst);
        debug_assert!(src_offset_bytes + bytes <= src.bucket_bytes());
        // SAFETY: caller guarantees layout equivalence.
        let dst_bytes: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr().cast::<u8>(), bytes) };
        let (ptr, _hold) = src.slice().device_ptr(&self.stream);
        // SAFETY: device pointer + offset is in-bounds; caller is
        // responsible for synchronising before reading `dst`.
        unsafe {
            result::memcpy_dtoh_async(
                dst_bytes,
                ptr + src_offset_bytes as sys::CUdeviceptr,
                self.stream.cu_stream(),
            )
            .map_err(driver_err)
        }
    }

    /// Download raw bytes (no type assumption). Synchronous.
    pub fn download_bytes(
        &self,
        src: &PooledBuffer,
        src_offset_bytes: usize,
        dst: &mut [u8],
    ) -> Result<(), String> {
        self.download_bytes_async(src, src_offset_bytes, dst)?;
        self.synchronize()
    }

    /// Asynchronous raw-byte download (no implicit synchronise).
    pub fn download_bytes_async(
        &self,
        src: &PooledBuffer,
        src_offset_bytes: usize,
        dst: &mut [u8],
    ) -> Result<(), String> {
        if dst.is_empty() {
            return Ok(());
        }
        debug_assert!(src_offset_bytes + dst.len() <= src.bucket_bytes());
        let (ptr, _hold) = src.slice().device_ptr(&self.stream);
        // SAFETY: caller must synchronise before reading `dst`.
        unsafe {
            result::memcpy_dtoh_async(
                dst,
                ptr + src_offset_bytes as sys::CUdeviceptr,
                self.stream.cu_stream(),
            )
            .map_err(driver_err)
        }
    }

    /// Device-to-device byte copy (`bytes` bytes from
    /// `src[src_offset_bytes..]` into `dst[dst_offset_bytes..]`).
    pub fn memcpy_dtod_bytes(
        &self,
        dst: &PooledBuffer,
        dst_offset_bytes: usize,
        src: &PooledBuffer,
        src_offset_bytes: usize,
        bytes: usize,
    ) -> Result<(), String> {
        if bytes == 0 {
            return Ok(());
        }
        debug_assert!(dst_offset_bytes + bytes <= dst.bucket_bytes());
        debug_assert!(src_offset_bytes + bytes <= src.bucket_bytes());
        let (dst_ptr, _hold_d) = dst.slice().device_ptr(&self.stream);
        let (src_ptr, _hold_s) = src.slice().device_ptr(&self.stream);
        // SAFETY: ranges are in-bounds; both buffers belong to this stream.
        unsafe {
            result::memcpy_dtod_async(
                dst_ptr + dst_offset_bytes as sys::CUdeviceptr,
                src_ptr + src_offset_bytes as sys::CUdeviceptr,
                bytes,
                self.stream.cu_stream(),
            )
        }
        .map_err(driver_err)
    }

    pub fn synchronize(&self) -> Result<(), String> {
        self.stream.synchronize().map_err(driver_err)
    }

    // ----- roots cache -----------------------------------------------------

    /// Roots-of-unity table for an `codeword_length`-point NTT. Stage layout
    /// matches the Metal backend exactly so the same kernel indexing works.
    pub fn roots_buffer(
        &self,
        codeword_length: usize,
    ) -> Result<Arc<CudaSlice<GpuField>>, String> {
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

        let buffer = self.stream.clone_htod(&roots).map_err(driver_err)?;
        let arc = Arc::new(buffer);
        cache.insert(codeword_length, Arc::clone(&arc));
        trace_event(format_args!(
            "roots cache miss codeword_length={codeword_length}"
        ));
        Ok(arc)
    }

    pub fn launch_cfg_1d(&self, work: usize) -> LaunchConfig {
        let block: u32 = self.max_block_size.max(1);
        let work = work.max(1) as u32;
        let grid = work.div_ceil(block);
        LaunchConfig {
            grid_dim:         (grid, 1, 1),
            block_dim:        (block, 1, 1),
            shared_mem_bytes: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PTX caching: hash (source, arch) and store under $XDG_CACHE_HOME/provekit
// so subsequent runs skip the (~hundreds of ms) nvrtc compile.
// ---------------------------------------------------------------------------

fn compile_or_load_ptx(source: &str, arch: Option<&'static str>) -> Result<Ptx, String> {
    let cache_path = ptx_cache_path(source, arch);
    if let Some(path) = cache_path.as_ref() {
        if let Ok(text) = fs::read_to_string(path) {
            trace_event(format_args!("ptx cache hit path={}", path.display()));
            return Ok(Ptx::from_src(text));
        }
    }
    let mut opts = CompileOptions::default();
    opts.options.push("-std=c++17".into());
    if let Some(arch) = arch {
        opts.arch = Some(arch);
    }
    let ptx = compile_ptx_with_opts(source, opts).map_err(|err| format!("nvrtc: {err:?}"))?;
    if let Some(path) = cache_path.as_ref() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, ptx.to_src());
        trace_event(format_args!("ptx cache wrote path={}", path.display()));
    }
    Ok(ptx)
}

fn ptx_cache_path(source: &str, arch: Option<&str>) -> Option<PathBuf> {
    let cache_root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    let mut hasher = DefaultHasher::new();
    "provekit-cuda-ntt".hash(&mut hasher);
    arch.unwrap_or("generic").hash(&mut hasher);
    source.hash(&mut hasher);
    Some(
        cache_root
            .join("provekit")
            .join("cuda")
            .join(format!(
                "ntt-{}-{:016x}.ptx",
                arch.unwrap_or("generic"),
                hasher.finish()
            )),
    )
}

fn arch_for_compute_capability(major: i32, minor: i32) -> Option<&'static str> {
    match (major, minor) {
        (5, 0) => Some("compute_50"),
        (5, 2) => Some("compute_52"),
        (6, 0) => Some("compute_60"),
        (6, 1) => Some("compute_61"),
        (7, 0) => Some("compute_70"),
        (7, 5) => Some("compute_75"),
        (8, 0) => Some("compute_80"),
        (8, 6) => Some("compute_86"),
        (8, 9) => Some("compute_89"),
        (9, 0) => Some("compute_90"),
        _ => None,
    }
}

fn driver_err(err: DriverError) -> String {
    format!("{err:?}")
}

fn bucket_bytes(bytes: usize) -> usize {
    if bytes == 0 {
        0
    } else {
        bytes.next_power_of_two()
    }
}
