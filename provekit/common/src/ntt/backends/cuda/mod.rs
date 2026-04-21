#[cfg(target_os = "linux")]
mod commit;
#[cfg(target_os = "linux")]
mod encode;
#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod field;
mod logging;
#[cfg(target_os = "linux")]
mod types;

#[cfg(target_os = "linux")]
use {
    self::engine::CudaRuntime,
    std::{
        env,
        sync::{Arc, OnceLock},
    },
    tracing::info,
    whir::{hash::SHA2, protocols::matrix_commit::Config as MatrixCommitConfig},
};
use {
    self::logging::trace_event,
    crate::ntt::backends::RSFr,
    ark_bn254::Fr,
    ark_ff::{FftField, Field},
    tracing::instrument,
    whir::algebra::ntt::ReedSolomon,
};

/// CUDA-accelerated Reed–Solomon committer for BN254.
///
/// Mirrors the structure of the Metal backend in `backends/metal/`:
///   - implements `IrsCommitter<Fr>` (in `commit.rs`), so the encoded matrix
///     and the Merkle tree can stay on the GPU between `commit` and `open`,
///   - implements `ReedSolomon<Fr>` for code paths that don't go through
///     the IRS committer (`gpu_encode` / CPU fallback).
#[derive(Clone, Copy, Debug, Default)]
pub struct CudaBn254Ntt;

#[cfg(target_os = "linux")]
static RUNTIME: OnceLock<Result<Arc<CudaRuntime>, String>> = OnceLock::new();

impl CudaBn254Ntt {
    /// Minimum problem size at which the GPU path is used. Below these the
    /// CPU NTT (parallelised, SIMD-heavy) wins after subtracting per-call
    const MIN_GPU_TOTAL_ELEMENTS: usize = 1 << 18;
    const MIN_GPU_ROW_COUNT: usize = 64;

    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self, String> {
        if env::var_os("PROVEKIT_DISABLE_CUDA_NTT").is_some() {
            return Err("CUDA NTT disabled via PROVEKIT_DISABLE_CUDA_NTT".into());
        }

        match RUNTIME.get_or_init(|| CudaRuntime::new().map(Arc::new)) {
            Ok(runtime) => {
                let (cc_major, cc_minor) = runtime.compute_capability;
                info!(
                    device = %runtime.device_name,
                    compute_capability = format!("{cc_major}.{cc_minor}"),
                    "initialized CUDA BN254 NTT backend"
                );
                trace_event(format_args!(
                    "init device={} compute_capability={cc_major}.{cc_minor}",
                    runtime.device_name,
                ));
                Ok(Self)
            }
            Err(err) => Err(err.clone()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Result<Self, String> {
        Err("CUDA BN254 NTT is only available on Linux".into())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn runtime(&self) -> Result<&Arc<CudaRuntime>, String> {
        match RUNTIME.get() {
            Some(Ok(runtime)) => Ok(runtime),
            Some(Err(err)) => Err(err.clone()),
            None => Err("CUDA runtime not initialized".into()),
        }
    }

    fn supports_gpu_shape(codeword_length: usize, row_coeffs: &[&[Fr]]) -> bool {
        if row_coeffs.is_empty() {
            return false;
        }
        if codeword_length <= 1 || !codeword_length.is_power_of_two() {
            return false;
        }
        let total_elements = row_coeffs.len().saturating_mul(codeword_length);
        total_elements >= Self::MIN_GPU_TOTAL_ELEMENTS
            || row_coeffs.len() >= Self::MIN_GPU_ROW_COUNT
    }

    /// Only the SHA-2 hash family is implemented on GPU; for any other
    /// configuration we fall back to the CPU committer.
    #[cfg(target_os = "linux")]
    fn supports_gpu_commit(matrix_commit: &MatrixCommitConfig<Fr>) -> bool {
        matrix_commit.leaf_hash_id == SHA2
            && matrix_commit
                .merkle_tree
                .layers
                .iter()
                .all(|layer| layer.hash_id == SHA2)
    }
}

impl ReedSolomon<Fr> for CudaBn254Ntt {
    fn next_order(&self, size: usize) -> Option<usize> {
        let order = size.next_power_of_two();
        if order <= 1 << 28 { Some(order) } else { None }
    }

    fn evaluation_points(
        &self,
        masked_message_length: usize,
        codeword_length: usize,
        indices: &[usize],
    ) -> Vec<Fr> {
        let _ = masked_message_length;
        let generator = self.generator(codeword_length);
        indices
            .iter()
            .map(|i| {
                let bits = usize::BITS - (codeword_length - 1).leading_zeros();
                let k = if bits == 0 {
                    *i
                } else {
                    i.reverse_bits() >> (usize::BITS - bits)
                };
                generator.pow([k as u64])
            })
            .collect()
    }

    fn generator(&self, codeword_length: usize) -> Fr {
        Fr::get_root_of_unity(codeword_length as u64).unwrap()
    }

    /// Try GPU encode first; fall back to CPU on shape mismatch or any GPU
    /// error. (The IRS committer path in `commit.rs` is what actually keeps
    /// the matrix on device for the WHIR open phase.)
    #[instrument(skip(self, messages, masks), fields(
        num_messages = messages.len(),
        message_len = messages.first().map(|c| c.len()),
        codeword_length = codeword_length,
        mask_len = masks.len().checked_div(messages.len())
    ))]
    fn interleaved_encode(
        &self,
        messages: &[&[Fr]],
        masks: &[Fr],
        codeword_length: usize,
    ) -> Vec<Fr> {
        if messages.is_empty() {
            return vec![];
        }

        let num_messages = messages.len();
        let message_length = messages[0].len();
        for message in messages {
            assert_eq!(message_length, message.len());
        }
        assert!(masks.len().is_multiple_of(num_messages));

        if !Self::supports_gpu_shape(codeword_length, messages) {
            trace_event(format_args!(
                "encode fallback path=cpu codeword_length={} rows={} reason=unsupported-shape",
                codeword_length, num_messages,
            ));
            return RSFr.interleaved_encode(messages, masks, codeword_length);
        }

        #[cfg(target_os = "linux")]
        {
            match self.gpu_encode(messages, masks, codeword_length) {
                Ok(codeword) => return codeword,
                Err(err) => {
                    trace_event(format_args!(
                        "encode fallback path=cpu codeword_length={} rows={} reason=gpu-error \
                         error={}",
                        codeword_length, num_messages, err,
                    ));
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        trace_event(format_args!(
            "encode fallback path=cpu codeword_length={} rows={} reason=unsupported-platform",
            codeword_length, num_messages,
        ));

        RSFr.interleaved_encode(messages, masks, codeword_length)
    }
}
