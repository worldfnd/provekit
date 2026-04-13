use {
    super::{
        field::{fr_to_gpu, gpu_to_fr},
        logging::trace_event,
        types::{
            DeviceMatrix, EncodeShape, GpuField, NttStageParams, ReplicateCosetsParams,
            TransposeParams,
        },
        MetalBn254Ntt,
    },
    ark_bn254::Fr,
    ark_ff::AdditiveGroup,
    metal::{MTLSize, NSUInteger},
    rayon::prelude::*,
    std::{ffi::c_void, mem::size_of},
    tracing::instrument,
    whir::algebra::ntt::ReedSolomon,
};

impl MetalBn254Ntt {
    #[instrument(skip(self, messages, masks), fields(
        num_messages = messages.len(),
        message_len = messages.first().map(|c| c.len()),
        codeword_length = codeword_length,
        mask_len = masks.len().checked_div(messages.len())
    ))]
    pub fn gpu_encode(
        &self,
        messages: &[&[Fr]],
        masks: &[Fr],
        codeword_length: usize,
    ) -> Result<Vec<Fr>, String> {
        let matrix = self.encode_matrix(messages, masks, codeword_length)?;
        let fields = self
            .runtime()?
            .buffer_slice::<GpuField>(matrix.buffer.as_ref(), matrix.rows * matrix.cols);
        if matrix.rows == 0 || matrix.cols == 0 {
            return Ok(Vec::new());
        }

        let mut output = vec![Fr::ZERO; matrix.rows * matrix.cols];
        output
            .par_chunks_mut(matrix.cols)
            .enumerate()
            .for_each(|(dst_row, dst)| {
                let natural_row = reverse_bit_index(dst_row, matrix.rows);
                let src_start = natural_row * matrix.cols;
                let src = &fields[src_start..src_start + matrix.cols];
                dst.iter_mut()
                    .zip(src.iter().copied())
                    .for_each(|(dst, src)| *dst = gpu_to_fr(src));
            });
        Ok(output)
    }

    #[instrument(skip(self, messages, masks), fields(
        num_messages = messages.len(),
        message_len = messages.first().map(|c| c.len()),
        codeword_length = codeword_length,
        mask_len = masks.len().checked_div(messages.len())
    ))]
    pub fn encode_matrix(
        &self,
        messages: &[&[Fr]],
        masks: &[Fr],
        codeword_length: usize,
    ) -> Result<DeviceMatrix, String> {
        let runtime = self.runtime()?;
        let shape = Self::encode_shape(messages, masks, codeword_length)?;
        if shape.total_elements == 0 {
            return Ok(DeviceMatrix {
                rows:   0,
                cols:   0,
                buffer: runtime.pooled_buffer::<GpuField>(0),
            });
        }

        trace_event(format_args!(
            "encode rows={} codeword_length={} num_cosets={} coset_size={} polynomials={} \
             path=coset",
            shape.row_count,
            codeword_length,
            shape.num_cosets,
            shape.coset_size,
            messages.len(),
        ));

        let current = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        runtime.zero_buffer::<GpuField>(current.as_ref(), shape.total_elements);
        pack_messages_and_masks_into_buffer(
            runtime.buffer_slice_mut(current.as_ref(), shape.total_elements),
            messages,
            masks,
            shape,
        );
        let roots = runtime.roots_buffer(codeword_length)?;

        let scratch = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        let transposed = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        let stage_count = codeword_length.trailing_zeros() as usize;
        let skipped_stage_count = shape.num_cosets.trailing_zeros() as usize;
        let total_butterflies = shape.total_elements / 2;
        let stage_threads =
            runtime.threads_per_threadgroup(&runtime.ntt_stage_pipeline, total_butterflies);
        let transpose_threads =
            runtime.threads_per_threadgroup(&runtime.transpose_pipeline, shape.total_elements);
        let transpose_params = TransposeParams {
            rows:           shape.row_count as u32,
            cols:           shape.codeword_length as u32,
            total_elements: shape.total_elements as u32,
        };

        let command_buffer = runtime.queue.new_command_buffer();
        let replicate_params = ReplicateCosetsParams {
            row_len:           shape.codeword_length as u32,
            coset_size:        shape.coset_size as u32,
            trailing_elements: shape
                .row_count
                .saturating_mul(shape.codeword_length - shape.coset_size)
                as u32,
        };
        if replicate_params.trailing_elements != 0 {
            let replicate_encoder = command_buffer.new_compute_command_encoder();
            replicate_encoder.set_compute_pipeline_state(&runtime.replicate_cosets_pipeline);
            replicate_encoder.set_buffer(0, Some(current.as_ref()), 0);
            replicate_encoder.set_bytes(
                1,
                size_of::<ReplicateCosetsParams>() as u64,
                (&replicate_params as *const ReplicateCosetsParams).cast::<c_void>(),
            );
            let replicate_threads = runtime.threads_per_threadgroup(
                &runtime.replicate_cosets_pipeline,
                replicate_params.trailing_elements as usize,
            );
            replicate_encoder.dispatch_threads(
                MTLSize {
                    width:  replicate_params.trailing_elements as u64,
                    height: 1,
                    depth:  1,
                },
                replicate_threads,
            );
            replicate_encoder.end_encoding();
        }
        let stage_encoder = command_buffer.new_compute_command_encoder();
        stage_encoder.set_compute_pipeline_state(&runtime.ntt_stage_pipeline);

        let mut twiddle_offset = (1usize << skipped_stage_count).saturating_sub(1);
        let mut source_is_current = true;
        for stage in skipped_stage_count..stage_count {
            let stride = codeword_length >> (stage + 1);
            let params = NttStageParams {
                row_len:        shape.codeword_length as u32,
                stride:         stride as u32,
                twiddle_offset: twiddle_offset as u32,
                _pad0:          0,
            };
            if source_is_current {
                stage_encoder.set_buffer(0, Some(current.as_ref()), 0);
                stage_encoder.set_buffer(1, Some(scratch.as_ref()), 0);
            } else {
                stage_encoder.set_buffer(0, Some(scratch.as_ref()), 0);
                stage_encoder.set_buffer(1, Some(current.as_ref()), 0);
            }
            stage_encoder.set_buffer(2, Some(roots.as_ref()), 0);
            stage_encoder.set_bytes(
                3,
                size_of::<NttStageParams>() as NSUInteger,
                (&params as *const NttStageParams).cast::<c_void>(),
            );
            stage_encoder.dispatch_threads(
                MTLSize {
                    width:  total_butterflies as u64,
                    height: 1,
                    depth:  1,
                },
                stage_threads,
            );
            twiddle_offset += 1usize << stage;
            source_is_current = !source_is_current;
        }
        stage_encoder.end_encoding();

        let final_source =
            choose_final_buffer(stage_count - skipped_stage_count, &current, &scratch);
        let transpose_encoder = command_buffer.new_compute_command_encoder();
        transpose_encoder.set_compute_pipeline_state(&runtime.transpose_pipeline);
        transpose_encoder.set_buffer(0, Some(final_source.as_ref()), 0);
        transpose_encoder.set_buffer(1, Some(transposed.as_ref()), 0);
        transpose_encoder.set_bytes(
            2,
            size_of::<TransposeParams>() as NSUInteger,
            (&transpose_params as *const TransposeParams).cast::<c_void>(),
        );
        transpose_encoder.dispatch_threads(
            MTLSize {
                width:  shape.total_elements as u64,
                height: 1,
                depth:  1,
            },
            transpose_threads,
        );
        transpose_encoder.end_encoding();

        command_buffer.commit();
        command_buffer.wait_until_completed();

        Ok(DeviceMatrix {
            rows:   shape.codeword_length,
            cols:   shape.row_count,
            buffer: transposed,
        })
    }

    pub fn encode_shape(
        messages: &[&[Fr]],
        masks: &[Fr],
        codeword_length: usize,
    ) -> Result<EncodeShape, String> {
        if messages.is_empty() {
            return Ok(EncodeShape {
                row_count: 0,
                codeword_length,
                coset_size: 0,
                message_length: 0,
                mask_length: 0,
                num_cosets: 0,
                total_elements: 0,
            });
        }
        if !Self::supports_gpu_shape(codeword_length, messages) {
            return Err("problem shape unsupported for GPU path".into());
        }

        let row_count = messages.len();
        let message_length = messages[0].len();
        if messages.iter().any(|row| row.len() != message_length) {
            return Err("all messages must have the same length".into());
        }
        if !masks.len().is_multiple_of(row_count) {
            return Err("mask count must be divisible by row count".into());
        }
        let mask_length = masks.len() / row_count;
        let masked_message_length = message_length + mask_length;
        let mut coset_size = Self::default()
            .next_order(masked_message_length)
            .ok_or_else(|| "no supported coset size for encode".to_string())?;
        while !codeword_length.is_multiple_of(coset_size) {
            coset_size = Self::default()
                .next_order(coset_size + 1)
                .ok_or_else(|| "no supported coset size for encode".to_string())?;
        }
        let num_cosets = codeword_length / coset_size;

        let total_elements = row_count
            .checked_mul(codeword_length)
            .ok_or_else(|| "GPU encode launch exceeds current 32-bit grid limit".to_string())?;
        if total_elements > u32::MAX as usize {
            return Err("GPU encode launch exceeds current 32-bit grid limit".into());
        }

        Ok(EncodeShape {
            row_count,
            codeword_length,
            coset_size,
            message_length,
            mask_length,
            num_cosets,
            total_elements,
        })
    }

    #[cfg(all(test, target_os = "macos"))]
    pub fn gpu_mul_pairs(&self, lhs: &[Fr], rhs: &[Fr]) -> Result<Vec<Fr>, String> {
        if lhs.len() != rhs.len() {
            return Err("lhs/rhs length mismatch".into());
        }

        let runtime = self.runtime()?;
        let count = lhs.len();
        if count == 0 {
            return Ok(Vec::new());
        }
        if count > u32::MAX as usize {
            return Err("GPU field multiplication launch exceeds current 32-bit grid limit".into());
        }

        let lhs_buffer = runtime.pooled_buffer::<GpuField>(count);
        let rhs_buffer = runtime.pooled_buffer::<GpuField>(count);
        fill_linear_buffer(runtime.buffer_slice_mut(lhs_buffer.as_ref(), count), lhs);
        fill_linear_buffer(runtime.buffer_slice_mut(rhs_buffer.as_ref(), count), rhs);
        let output = runtime.pooled_buffer::<GpuField>(count);

        let command_buffer = runtime.queue.new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&runtime.field_mul_pipeline);
        encoder.set_buffer(0, Some(lhs_buffer.as_ref()), 0);
        encoder.set_buffer(1, Some(rhs_buffer.as_ref()), 0);
        encoder.set_buffer(2, Some(output.as_ref()), 0);
        let params = super::types::FieldMulParams {
            count: count as u32,
        };
        encoder.set_bytes(
            3,
            size_of::<super::types::FieldMulParams>() as NSUInteger,
            (&params as *const super::types::FieldMulParams).cast::<c_void>(),
        );
        let threads = runtime.threads_per_threadgroup(&runtime.field_mul_pipeline, count);
        encoder.dispatch_threads(
            MTLSize {
                width:  count as u64,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();

        Ok(runtime
            .buffer_slice::<GpuField>(output.as_ref(), count)
            .iter()
            .copied()
            .map(gpu_to_fr)
            .collect())
    }
}

fn pack_messages_and_masks_into_buffer(
    packed: &mut [GpuField],
    messages: &[&[Fr]],
    masks: &[Fr],
    shape: EncodeShape,
) {
    packed
        .par_chunks_mut(shape.codeword_length)
        .enumerate()
        .for_each(|(row_index, row)| {
            for (dst, &coeff) in row[..shape.message_length]
                .iter_mut()
                .zip(messages[row_index])
            {
                *dst = fr_to_gpu(coeff);
            }
            for mask_column in 0..shape.mask_length {
                row[shape.message_length + mask_column] =
                    fr_to_gpu(masks[mask_column * shape.row_count + row_index]);
            }
        });
}

#[cfg(all(test, target_os = "macos"))]
fn fill_linear_buffer(dst: &mut [GpuField], src: &[Fr]) {
    dst.par_iter_mut()
        .enumerate()
        .for_each(|(index, dst)| *dst = fr_to_gpu(src[index]));
}

fn choose_final_buffer<'a>(
    stage_count: usize,
    current: &'a super::engine::PooledBuffer,
    scratch: &'a super::engine::PooledBuffer,
) -> &'a super::engine::PooledBuffer {
    if stage_count.is_multiple_of(2) {
        current
    } else {
        scratch
    }
}

fn reverse_bit_index(index: usize, codeword_length: usize) -> usize {
    let bits = usize::BITS - (codeword_length - 1).leading_zeros();
    if bits == 0 {
        index
    } else {
        index.reverse_bits() >> (usize::BITS - bits)
    }
}
