#[cfg(target_os = "macos")]
mod commit;
#[cfg(target_os = "macos")]
mod encode;
#[cfg(target_os = "macos")]
mod engine;
#[cfg(target_os = "macos")]
mod field;
mod logging;
#[cfg(target_os = "macos")]
mod types;
#[cfg(target_os = "macos")]
#[path = "whir.rs"]
mod whir_accel;

#[cfg(target_os = "macos")]
use self::engine::MetalRuntime;
#[cfg(target_os = "macos")]
use objc2_metal::{MTLComputePipelineState, MTLDevice};
#[cfg(target_os = "macos")]
use std::{
    env,
    sync::{Arc, OnceLock},
};
#[cfg(target_os = "macos")]
use tracing::info;
#[cfg(target_os = "macos")]
use whir::{hash::SHA2, protocols::matrix_commit::Config as MatrixCommitConfig};
use {
    self::logging::trace_event,
    crate::ntt::backends::RSFr,
    ark_bn254::Fr,
    ark_ff::{FftField, Field},
    tracing::instrument,
    whir::algebra::ntt::ReedSolomon,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct MetalBn254Ntt;

#[cfg(target_os = "macos")]
static RUNTIME: OnceLock<Result<Arc<MetalRuntime>, String>> = OnceLock::new();

impl MetalBn254Ntt {
    const MIN_GPU_TOTAL_ELEMENTS: usize = 1 << 20;
    const MIN_GPU_ROW_COUNT: usize = 64;

    #[cfg(target_os = "macos")]
    pub fn new() -> Result<Self, String> {
        if env::var_os("PROVEKIT_DISABLE_METAL_NTT").is_some() {
            return Err("Metal NTT disabled via PROVEKIT_DISABLE_METAL_NTT".into());
        }

        match RUNTIME.get_or_init(|| MetalRuntime::new().map(Arc::new)) {
            Ok(runtime) => {
                info!(
                    device = %runtime.device.name(),
                    thread_execution_width = runtime.ntt_stage_pipeline.threadExecutionWidth(),
                    max_total_threads_per_threadgroup = runtime
                        .ntt_stage_pipeline
                        .maxTotalThreadsPerThreadgroup(),
                    "initialized Metal BN254 NTT backend"
                );
                trace_event(format_args!(
                    "init device={} thread_execution_width={} max_total_threads_per_threadgroup={}",
                    runtime.device.name(),
                    runtime.ntt_stage_pipeline.threadExecutionWidth(),
                    runtime.ntt_stage_pipeline.maxTotalThreadsPerThreadgroup(),
                ));
                Ok(Self)
            }
            Err(err) => Err(err.clone()),
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn new() -> Result<Self, String> {
        Err("Metal BN254 NTT is only available on macOS".into())
    }

    #[cfg(target_os = "macos")]
    pub fn runtime(&self) -> Result<&Arc<MetalRuntime>, String> {
        match RUNTIME.get() {
            Some(Ok(runtime)) => Ok(runtime),
            Some(Err(err)) => Err(err.clone()),
            None => Err("metal runtime not initialized".into()),
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

    #[cfg(target_os = "macos")]
    fn supports_gpu_commit(matrix_commit: &MatrixCommitConfig<Fr>) -> bool {
        matrix_commit.leaf_hash_id == SHA2
            && matrix_commit
                .merkle_tree
                .layers
                .iter()
                .all(|layer| layer.hash_id == SHA2)
    }
}

impl ReedSolomon<Fr> for MetalBn254Ntt {
    /// @dev: Metal does not need next_order.
    /// implementing this because trait requires it.
    fn next_order(&self, size: usize) -> Option<usize> {
        let order = size.next_power_of_two();
        if order <= 1 << 28 {
            Some(order)
        } else {
            None
        }
    }

    /// @dev: Metal does not need evaluation_points.
    /// implementing this because trait requires it.
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

    /// @dev: Metal does not need generator.
    /// implementing this because trait requires it.
    fn generator(&self, codeword_length: usize) -> Fr {
        Fr::get_root_of_unity(codeword_length as u64).unwrap()
    }

    /// @note: tries GPU encode first, falls back to CPU if workload is too
    /// small or too large, or if GPU fails.
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
        let _mask_length = masks.len() / num_messages;
        if !Self::supports_gpu_shape(codeword_length, messages) {
            trace_event(format_args!(
                "encode fallback path=cpu codeword_length={} rows={} reason=unsupported-shape",
                codeword_length, num_messages,
            ));
            return RSFr.interleaved_encode(messages, masks, codeword_length);
        }

        #[cfg(target_os = "macos")]
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

        #[cfg(not(target_os = "macos"))]
        trace_event(format_args!(
            "encode fallback path=cpu codeword_length={} rows={} reason=unsupported-platform",
            codeword_length, num_messages,
        ));

        RSFr.interleaved_encode(messages, masks, codeword_length)
    }
}
