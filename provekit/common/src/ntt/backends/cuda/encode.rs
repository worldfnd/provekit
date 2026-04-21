use {
    super::{
        logging::trace_event,
        types::{
            BitReverseParams, DeviceMatrix, EncodeShape, GpuField, NttStageParams,
            ReplicateCosetsParams, TransposeParams,
        },
        CudaBn254Ntt,
    },
    ark_bn254::Fr,
    cudarc::driver::PushKernelArg,
    std::mem::{align_of, size_of},
    tracing::instrument,
    whir::algebra::ntt::ReedSolomon,
};

impl CudaBn254Ntt {
    /// Public entry point used by `ReedSolomon::interleaved_encode`. Runs the
    /// GPU encode and downloads the resulting matrix into a `Vec<Fr>`.
    ///
    /// The `IrsCommitter` path uses `encode_matrix` directly to keep the
    /// matrix on device.
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
        // We rely on Fr having identical memory layout to GpuField (4×u64
        // Montgomery limbs). This lets us host↔device memcpy &[Fr] slices
        // directly, avoiding a host pack/unpack pass.
        const _: () = assert!(size_of::<Fr>() == size_of::<GpuField>());
        const _: () = assert!(align_of::<Fr>() == align_of::<GpuField>());

        let matrix = self.encode_matrix(messages, masks, codeword_length)?;
        if matrix.rows == 0 || matrix.cols == 0 {
            return Ok(Vec::new());
        }
        let runtime = self.runtime()?;

        // Read back the full matrix into a host Vec<Fr>, applying the
        // bit-reversal of the codeword index so the output matches the CPU
        // ordering (host row r ⇄ codeword index r).
        let total = matrix.rows * matrix.cols;
        let mut host_buf: Vec<Fr> = Vec::with_capacity(total);
        // SAFETY: every element is overwritten by the memcpy below before
        // we read from `output`. Capacity is exactly `total`.
        unsafe { host_buf.set_len(total) };
        // SAFETY: Fr has identical layout to GpuField (asserted above);
        // bytes copied = total * sizeof(GpuField).
        unsafe {
            runtime.download_into::<Fr>(&matrix.buffer, 0, &mut host_buf)?;
        }

        // The on-device layout is [codeword_index_in_BR_order][message_index].
        // Apply bit-reversal of the row index to produce natural codeword
        // order.
        let cols = matrix.cols;
        let rows = matrix.rows;
        let mut output: Vec<Fr> = Vec::with_capacity(total);
        // SAFETY: capacity == total; every element overwritten by the loop.
        unsafe { output.set_len(total) };
        for dst_row in 0..rows {
            let natural_row = reverse_bit_index(dst_row, rows);
            let src_start = natural_row * cols;
            let dst_start = dst_row * cols;
            output[dst_start..dst_start + cols]
                .copy_from_slice(&host_buf[src_start..src_start + cols]);
        }
        Ok(output)
    }

    /// Encode the messages and masks into a device matrix. The returned
    /// `DeviceMatrix.buffer` holds the encoded values laid out as
    /// `[codeword_index_in_BR_order, message_index]` (row-major), with
    /// `rows = codeword_length`, `cols = message_count`. Lifetime of the
    /// buffer is tied to the returned `DeviceMatrix` (Arc'd via the pool).
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

        // Working buffer, zero-initialised so the unused tail of each row
        // (between message_length+mask_length and coset_size) is zero before
        // the replicate step overwrites the rest of the row.
        let current = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        runtime.memset_zeros(&current, 0, shape.total_elements * size_of::<GpuField>())?;

        // Upload messages and masks directly from the caller's &[Fr] slices,
        // bypassing any host-side pack pass. (Fr ↔ GpuField layout is
        // asserted equivalent.)
        for (row_index, msg) in messages.iter().enumerate() {
            let dst_offset = (row_index * shape.codeword_length) * size_of::<GpuField>();
            // SAFETY: layout equivalence asserted; range fits in current.
            unsafe {
                runtime.upload_into::<Fr>(msg, &current, dst_offset)?;
            }
        }
        if shape.mask_length != 0 {
            // Masks are laid out [mask_col][row] in the caller's slice but we
            // need them at [row][message_length + mask_col] in the device
            // buffer. Pack on host into a small contiguous staging buffer,
            // then upload per row (mask_length is typically very small).
            let mut staging: Vec<Fr> = vec![Fr::default(); shape.mask_length];
            for row_index in 0..shape.row_count {
                for mask_col in 0..shape.mask_length {
                    staging[mask_col] = masks[mask_col * shape.row_count + row_index];
                }
                let dst_offset = (row_index * shape.codeword_length + shape.message_length)
                    * size_of::<GpuField>();
                // SAFETY: layout equivalence; range fits in current.
                unsafe {
                    runtime.upload_into::<Fr>(&staging, &current, dst_offset)?;
                }
            }
        }

        let roots = runtime.roots_buffer(codeword_length)?;
        let transposed = runtime.pooled_buffer::<GpuField>(shape.total_elements);

        let stage_count = codeword_length.trailing_zeros() as usize;
        let skipped_stage_count = shape.num_cosets.trailing_zeros() as usize;
        let total_butterflies = shape.total_elements / 2;

        // 1. Replicate the first coset across the rest of each row.
        let replicate_params = ReplicateCosetsParams {
            row_len:           shape.codeword_length as u32,
            coset_size:        shape.coset_size as u32,
            trailing_elements: shape
                .row_count
                .saturating_mul(shape.codeword_length - shape.coset_size)
                as u32,
        };
        if replicate_params.trailing_elements != 0 {
            let cfg = runtime.launch_cfg_1d(replicate_params.trailing_elements as usize);
            // SAFETY: kernel signature matches arg list; arrays in-bounds.
            unsafe {
                runtime
                    .stream
                    .launch_builder(&runtime.replicate_cosets_function)
                    .arg(current.slice())
                    .arg(&replicate_params)
                    .launch(cfg)
            }
            .map_err(|e| format!("launch replicate_first_coset: {e:?}"))?;
        }

        // 2. Bit-reverse permute each row (so the subsequent NTT proceeds
        //    in natural-order indexing through twiddles).
        let bit_reverse_params = BitReverseParams {
            row_len:        shape.codeword_length as u32,
            log_n:          stage_count as u32,
            total_elements: shape.total_elements as u32,
            _pad0:          0,
        };
        {
            let cfg = runtime.launch_cfg_1d(shape.total_elements);
            // SAFETY: kernel signature matches; in-bounds.
            unsafe {
                runtime
                    .stream
                    .launch_builder(&runtime.bit_reverse_function)
                    .arg(current.slice())
                    .arg(&bit_reverse_params)
                    .launch(cfg)
            }
            .map_err(|e| format!("launch bit_reverse: {e:?}"))?;
        }

        // 3. Iteratively run NTT butterfly stages.
        let mut twiddle_offset = (1usize << skipped_stage_count).saturating_sub(1);
        let total_butterflies_u32 = total_butterflies as u32;
        for stage in skipped_stage_count..stage_count {
            let half_m = 1usize << stage;
            let params = NttStageParams {
                row_len:        shape.codeword_length as u32,
                half_m:         half_m as u32,
                twiddle_offset: twiddle_offset as u32,
                _pad0:          0,
            };
            let cfg = runtime.launch_cfg_1d(total_butterflies);
            // SAFETY: kernel signature matches; ranges in-bounds.
            unsafe {
                runtime
                    .stream
                    .launch_builder(&runtime.ntt_stage_function)
                    .arg(current.slice())
                    .arg(&*roots)
                    .arg(&params)
                    .arg(&total_butterflies_u32)
                    .launch(cfg)
            }
            .map_err(|e| format!("launch ntt_stage(stage={stage}): {e:?}"))?;
            twiddle_offset += 1usize << stage;
        }

        // 4. Transpose to [codeword_index_in_BR_order][message_index].
        let transpose_params = TransposeParams {
            rows:           shape.row_count as u32,
            cols:           shape.codeword_length as u32,
            total_elements: shape.total_elements as u32,
        };
        {
            let cfg = runtime.launch_cfg_1d(shape.total_elements);
            // SAFETY: kernel signature matches; ranges in-bounds.
            unsafe {
                runtime
                    .stream
                    .launch_builder(&runtime.transpose_function)
                    .arg(current.slice())
                    .arg(transposed.slice())
                    .arg(&transpose_params)
                    .launch(cfg)
            }
            .map_err(|e| format!("launch transpose: {e:?}"))?;
        }

        // Synchronise so that `current` can be safely returned to the pool
        // when it's dropped at the end of this function.
        runtime.synchronize()?;

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
        let mut coset_size = Self
            .next_order(masked_message_length)
            .ok_or_else(|| "no supported coset size for encode".to_string())?;
        while !codeword_length.is_multiple_of(coset_size) {
            coset_size = Self
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

fn reverse_bit_index(index: usize, codeword_length: usize) -> usize {
    let bits = usize::BITS - (codeword_length - 1).leading_zeros();
    if bits == 0 {
        index
    } else {
        index.reverse_bits() >> (usize::BITS - bits)
    }
}
