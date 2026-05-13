use {
    super::{
        engine::{
            check_command_buffer, new_command_buffer, new_compute_encoder, set_buffer, set_bytes,
        },
        field::{fr_to_gpu, gpu_to_fr},
        logging::trace_event,
        types::{
            BitReverseParams, DeviceMatrix, EncodeShape, GpuField, NttStageParams,
            PackDeviceVectorParams, ReplicateCosetsParams, TransposeParams,
        },
        MetalBn254Ntt,
    },
    ark_bn254::Fr,
    ark_ff::AdditiveGroup,
    objc2_metal::{MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLSize},
    rayon::prelude::*,
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

        let transposed = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        let stage_count = codeword_length.trailing_zeros() as usize;
        let skipped_stage_count = shape.num_cosets.trailing_zeros() as usize;
        let total_butterflies = shape.total_elements / 2;
        let bit_reverse_threads =
            runtime.threads_per_threadgroup(&runtime.bit_reverse_pipeline, shape.total_elements);
        let stage_threads =
            runtime.threads_per_threadgroup(&runtime.ntt_stage_pipeline, total_butterflies);
        let transpose_threads =
            runtime.threads_per_threadgroup(&runtime.transpose_pipeline, shape.total_elements);
        let bit_reverse_params = BitReverseParams {
            row_len:        shape.codeword_length as u32,
            log_n:          stage_count as u32,
            total_elements: shape.total_elements as u32,
            _pad0:          0,
        };
        let transpose_params = TransposeParams {
            rows:           shape.row_count as u32,
            cols:           shape.codeword_length as u32,
            total_elements: shape.total_elements as u32,
        };

        let command_buffer = new_command_buffer(&runtime.queue)?;
        let replicate_params = ReplicateCosetsParams {
            row_len:           shape.codeword_length as u32,
            coset_size:        shape.coset_size as u32,
            trailing_elements: shape
                .row_count
                .saturating_mul(shape.codeword_length - shape.coset_size)
                as u32,
        };
        if replicate_params.trailing_elements != 0 {
            let replicate_encoder = new_compute_encoder(&command_buffer)?;
            replicate_encoder.setComputePipelineState(&runtime.replicate_cosets_pipeline);
            set_buffer(&replicate_encoder, 0, current.as_ref(), 0);
            set_bytes(&replicate_encoder, 1, &replicate_params);
            let replicate_threads = runtime.threads_per_threadgroup(
                &runtime.replicate_cosets_pipeline,
                replicate_params.trailing_elements as usize,
            );
            replicate_encoder.dispatchThreads_threadsPerThreadgroup(
                MTLSize {
                    width:  replicate_params.trailing_elements as usize,
                    height: 1,
                    depth:  1,
                },
                replicate_threads,
            );
            replicate_encoder.endEncoding();
        }
        let bit_reverse_encoder = new_compute_encoder(&command_buffer)?;
        bit_reverse_encoder.setComputePipelineState(&runtime.bit_reverse_pipeline);
        set_buffer(&bit_reverse_encoder, 0, current.as_ref(), 0);
        set_bytes(&bit_reverse_encoder, 1, &bit_reverse_params);
        bit_reverse_encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  shape.total_elements,
                height: 1,
                depth:  1,
            },
            bit_reverse_threads,
        );
        bit_reverse_encoder.endEncoding();

        let stage_encoder = new_compute_encoder(&command_buffer)?;
        stage_encoder.setComputePipelineState(&runtime.ntt_stage_pipeline);

        let mut twiddle_offset = (1usize << skipped_stage_count).saturating_sub(1);
        for stage in skipped_stage_count..stage_count {
            let half_m = 1usize << stage;
            let params = NttStageParams {
                row_len:        shape.codeword_length as u32,
                half_m:         half_m as u32,
                twiddle_offset: twiddle_offset as u32,
                _pad0:          0,
            };
            set_buffer(&stage_encoder, 0, current.as_ref(), 0);
            set_buffer(&stage_encoder, 1, roots.as_ref(), 0);
            set_bytes(&stage_encoder, 2, &params);
            stage_encoder.dispatchThreads_threadsPerThreadgroup(
                MTLSize {
                    width:  total_butterflies,
                    height: 1,
                    depth:  1,
                },
                stage_threads,
            );
            twiddle_offset += 1usize << stage;
        }
        stage_encoder.endEncoding();

        let transpose_encoder = new_compute_encoder(&command_buffer)?;
        transpose_encoder.setComputePipelineState(&runtime.transpose_pipeline);
        set_buffer(&transpose_encoder, 0, current.as_ref(), 0);
        set_buffer(&transpose_encoder, 1, transposed.as_ref(), 0);
        set_bytes(&transpose_encoder, 2, &transpose_params);
        transpose_encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  shape.total_elements,
                height: 1,
                depth:  1,
            },
            transpose_threads,
        );
        transpose_encoder.endEncoding();

        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)?;

        Ok(DeviceMatrix {
            rows:   shape.codeword_length,
            cols:   shape.row_count,
            buffer: transposed,
        })
    }

    pub(super) fn encode_device_vector_matrix(
        &self,
        vector: &super::engine::Buffer,
        vector_len: usize,
        masks: &[Fr],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<DeviceMatrix, String> {
        if interleaving_depth == 0 || !vector_len.is_multiple_of(interleaving_depth) {
            return Err("device vector length must be divisible by interleaving depth".into());
        }
        if !masks.len().is_multiple_of(interleaving_depth) {
            return Err("mask count must be divisible by interleaving depth".into());
        }
        let message_length = vector_len / interleaving_depth;
        let mask_length = masks.len() / interleaving_depth;
        let masked_message_length = message_length + mask_length;
        let mut coset_size = self
            .next_order(masked_message_length)
            .ok_or_else(|| "no supported coset size for device-vector encode".to_string())?;
        while !codeword_length.is_multiple_of(coset_size) {
            coset_size = self
                .next_order(coset_size + 1)
                .ok_or_else(|| "no supported coset size for device-vector encode".to_string())?;
        }
        let shape = EncodeShape {
            row_count: interleaving_depth,
            codeword_length,
            coset_size,
            message_length,
            mask_length,
            num_cosets: codeword_length / coset_size,
            total_elements: interleaving_depth * codeword_length,
        };
        if shape.total_elements > u32::MAX as usize {
            return Err("GPU encode launch exceeds current 32-bit grid limit".into());
        }

        let runtime = self.runtime()?;
        let current = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        let masks_gpu = {
            let masks = masks.iter().copied().map(fr_to_gpu).collect::<Vec<_>>();
            runtime.buffer_with_data(&masks)
        };
        let roots = runtime.roots_buffer(codeword_length)?;

        let transposed = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        let stage_count = codeword_length.trailing_zeros() as usize;
        let skipped_stage_count = shape.num_cosets.trailing_zeros() as usize;
        let total_butterflies = shape.total_elements / 2;
        let pack_params = PackDeviceVectorParams {
            row_count:       shape.row_count as u32,
            codeword_length: shape.codeword_length as u32,
            message_length:  shape.message_length as u32,
            mask_length:     shape.mask_length as u32,
        };
        let bit_reverse_params = BitReverseParams {
            row_len:        shape.codeword_length as u32,
            log_n:          stage_count as u32,
            total_elements: shape.total_elements as u32,
            _pad0:          0,
        };
        let replicate_params = ReplicateCosetsParams {
            row_len:           shape.codeword_length as u32,
            coset_size:        shape.coset_size as u32,
            trailing_elements: shape
                .row_count
                .saturating_mul(shape.codeword_length - shape.coset_size)
                as u32,
        };
        let transpose_params = TransposeParams {
            rows:           shape.row_count as u32,
            cols:           shape.codeword_length as u32,
            total_elements: shape.total_elements as u32,
        };

        let command_buffer = new_command_buffer(&runtime.queue)?;
        let pack_encoder = new_compute_encoder(&command_buffer)?;
        pack_encoder.setComputePipelineState(&runtime.pack_device_vector_pipeline);
        set_buffer(&pack_encoder, 0, vector, 0);
        set_buffer(&pack_encoder, 1, &masks_gpu, 0);
        set_buffer(&pack_encoder, 2, current.as_ref(), 0);
        set_bytes(&pack_encoder, 3, &pack_params);
        let pack_threads = runtime
            .threads_per_threadgroup(&runtime.pack_device_vector_pipeline, shape.total_elements);
        pack_encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  shape.total_elements,
                height: 1,
                depth:  1,
            },
            pack_threads,
        );
        pack_encoder.endEncoding();

        if replicate_params.trailing_elements != 0 {
            let replicate_encoder = new_compute_encoder(&command_buffer)?;
            replicate_encoder.setComputePipelineState(&runtime.replicate_cosets_pipeline);
            set_buffer(&replicate_encoder, 0, current.as_ref(), 0);
            set_bytes(&replicate_encoder, 1, &replicate_params);
            let replicate_threads = runtime.threads_per_threadgroup(
                &runtime.replicate_cosets_pipeline,
                replicate_params.trailing_elements as usize,
            );
            replicate_encoder.dispatchThreads_threadsPerThreadgroup(
                MTLSize {
                    width:  replicate_params.trailing_elements as usize,
                    height: 1,
                    depth:  1,
                },
                replicate_threads,
            );
            replicate_encoder.endEncoding();
        }

        let bit_reverse_encoder = new_compute_encoder(&command_buffer)?;
        bit_reverse_encoder.setComputePipelineState(&runtime.bit_reverse_pipeline);
        set_buffer(&bit_reverse_encoder, 0, current.as_ref(), 0);
        set_bytes(&bit_reverse_encoder, 1, &bit_reverse_params);
        let bit_reverse_threads =
            runtime.threads_per_threadgroup(&runtime.bit_reverse_pipeline, shape.total_elements);
        bit_reverse_encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  shape.total_elements,
                height: 1,
                depth:  1,
            },
            bit_reverse_threads,
        );
        bit_reverse_encoder.endEncoding();

        let stage_encoder = new_compute_encoder(&command_buffer)?;
        stage_encoder.setComputePipelineState(&runtime.ntt_stage_pipeline);
        let mut twiddle_offset = (1usize << skipped_stage_count).saturating_sub(1);
        let stage_threads =
            runtime.threads_per_threadgroup(&runtime.ntt_stage_pipeline, total_butterflies);
        for stage in skipped_stage_count..stage_count {
            let half_m = 1usize << stage;
            let params = NttStageParams {
                row_len:        shape.codeword_length as u32,
                half_m:         half_m as u32,
                twiddle_offset: twiddle_offset as u32,
                _pad0:          0,
            };
            set_buffer(&stage_encoder, 0, current.as_ref(), 0);
            set_buffer(&stage_encoder, 1, roots.as_ref(), 0);
            set_bytes(&stage_encoder, 2, &params);
            stage_encoder.dispatchThreads_threadsPerThreadgroup(
                MTLSize {
                    width:  total_butterflies,
                    height: 1,
                    depth:  1,
                },
                stage_threads,
            );
            twiddle_offset += 1usize << stage;
        }
        stage_encoder.endEncoding();

        let transpose_encoder = new_compute_encoder(&command_buffer)?;
        transpose_encoder.setComputePipelineState(&runtime.transpose_pipeline);
        set_buffer(&transpose_encoder, 0, current.as_ref(), 0);
        set_buffer(&transpose_encoder, 1, transposed.as_ref(), 0);
        set_bytes(&transpose_encoder, 2, &transpose_params);
        let transpose_threads =
            runtime.threads_per_threadgroup(&runtime.transpose_pipeline, shape.total_elements);
        transpose_encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  shape.total_elements,
                height: 1,
                depth:  1,
            },
            transpose_threads,
        );
        transpose_encoder.endEncoding();

        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)?;

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

fn reverse_bit_index(index: usize, codeword_length: usize) -> usize {
    let bits = usize::BITS - (codeword_length - 1).leading_zeros();
    if bits == 0 {
        index
    } else {
        index.reverse_bits() >> (usize::BITS - bits)
    }
}
