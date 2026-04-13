#[path = "mod-main.rs"]
mod cpu;
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

pub use cpu::RSFr;

use {self::logging::trace_event, ark_bn254::Fr, whir::algebra::ntt::ReedSolomon};
#[cfg(target_os = "macos")]
use {
    self::engine::MetalRuntime,
    std::{
        env,
        sync::{Arc, OnceLock},
    },
    tracing::info,
    whir::{hash::SHA2, protocols::matrix_commit::Config as MatrixCommitConfig},
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
                    device = runtime.device.name(),
                    thread_execution_width = runtime.ntt_stage_pipeline.thread_execution_width(),
                    max_total_threads_per_threadgroup = runtime
                        .ntt_stage_pipeline
                        .max_total_threads_per_threadgroup(),
                    "initialized Metal BN254 NTT backend"
                );
                trace_event(format_args!(
                    "init device={} thread_execution_width={} max_total_threads_per_threadgroup={}",
                    runtime.device.name(),
                    runtime.ntt_stage_pipeline.thread_execution_width(),
                    runtime
                        .ntt_stage_pipeline
                        .max_total_threads_per_threadgroup(),
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
    fn runtime(&self) -> Result<&Arc<MetalRuntime>, String> {
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
        total_elements >= Self::MIN_GPU_TOTAL_ELEMENTS || row_coeffs.len() >= Self::MIN_GPU_ROW_COUNT
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
    fn next_order(&self, size: usize) -> Option<usize> {
        RSFr.next_order(size)
    }

    fn evaluation_points(
        &self,
        masked_message_length: usize,
        codeword_length: usize,
        indices: &[usize],
    ) -> Vec<Fr> {
        RSFr.evaluation_points(masked_message_length, codeword_length, indices)
    }

    fn generator(&self, codeword_length: usize) -> Fr {
        RSFr.generator(codeword_length)
    }

    fn interleaved_encode(
        &self,
        messages: &[&[Fr]],
        masks: &[Fr],
        codeword_length: usize,
    ) -> Vec<Fr> {
        let cpu = RSFr;
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
                codeword_length,
                num_messages,
            ));
            return cpu.interleaved_encode(messages, masks, codeword_length);
        }

        #[cfg(target_os = "macos")]
        {
            match self.gpu_encode(messages, masks, codeword_length) {
                Ok(codeword) => return codeword,
                Err(err) => {
                    trace_event(format_args!(
                        "encode fallback path=cpu codeword_length={} rows={} reason=gpu-error error={}",
                        codeword_length,
                        num_messages,
                        err,
                    ));
                }
            }
        }

        #[cfg(not(target_os = "macos"))]
        trace_event(format_args!(
            "encode fallback path=cpu codeword_length={} rows={} reason=unsupported-platform",
            codeword_length,
            num_messages,
        ));

        cpu.interleaved_encode(messages, masks, codeword_length)
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "tests.rs"]
mod tests;
