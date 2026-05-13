use {
    super::{
        engine::{
            check_command_buffer, new_command_buffer, new_compute_encoder, set_buffer, set_bytes,
            PooledBuffer,
        },
        field::gpu_to_fr,
        types::{
            DeviceMatrix, DeviceMerkleWitness, DeviceRows, EncodeFieldBytesParams,
            GatherHashesParams, GatherRowsParams, GpuField, HashManyParams,
        },
        MetalBn254Ntt,
    },
    ark_bn254::Fr,
    objc2_foundation::NSRange,
    objc2_metal::{
        MTLBlitCommandEncoder, MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder,
        MTLSize,
    },
    std::{mem::size_of, sync::Arc},
    whir::{
        hash::Hash,
        protocols::{
            irs_commit::{CpuIrsCommitter, IrsCommitArtifact, IrsCommitter, MatrixRows},
            matrix_commit::{Config as MatrixCommitConfig, Encodable},
            merkle_tree::WitnessTrait,
        },
    },
};

impl IrsCommitter<Fr> for MetalBn254Ntt {
    fn commit(
        &self,
        messages: &[&[Fr]],
        masks: &[Fr],
        codeword_length: usize,
        matrix_commit: &MatrixCommitConfig<Fr>,
    ) -> IrsCommitArtifact<Fr> {
        let cpu_commit = || {
            CpuIrsCommitter::new(Arc::new(crate::ntt::RSFr)).commit(
                messages,
                masks,
                codeword_length,
                matrix_commit,
            )
        };

        if !Self::supports_gpu_shape(codeword_length, messages)
            || !Self::supports_gpu_commit(matrix_commit)
        {
            return cpu_commit();
        }

        let Ok(matrix) = self.encode_matrix(messages, masks, codeword_length) else {
            return cpu_commit();
        };
        let Ok(leaf_hashes) = self.hash_rows_to_buffer(&matrix) else {
            return cpu_commit();
        };
        let Ok(merkle_witness) = self.build_merkle_witness(matrix_commit, &leaf_hashes) else {
            return cpu_commit();
        };

        IrsCommitArtifact {
            root:           merkle_witness.root(),
            rows:           Arc::new(DeviceRows {
                rows:   matrix.rows,
                cols:   matrix.cols,
                buffer: matrix.buffer,
            }),
            matrix_witness: merkle_witness,
        }
    }
}

impl MetalBn254Ntt {
    pub(super) fn hash_rows_to_buffer(
        &self,
        matrix: &DeviceMatrix,
    ) -> Result<PooledBuffer, String> {
        if matrix.rows == 0 {
            return Ok(self.runtime()?.pooled_buffer::<Hash>(0));
        }

        let runtime = self.runtime()?;
        let total_elements = matrix.rows * matrix.cols;
        let total_bytes = total_elements * Fr::encoded_size();
        let message_size = matrix.cols * Fr::encoded_size();
        if total_elements > u32::MAX as usize || message_size > u32::MAX as usize {
            return Err("GPU hash launch exceeds current 32-bit grid limit".into());
        }

        let encoded = runtime.pooled_bytes(total_bytes);
        let hashes = runtime.pooled_buffer::<Hash>(matrix.rows);
        let encode_params = EncodeFieldBytesParams {
            rows: matrix.rows as u32,
            cols: matrix.cols as u32,
        };
        let hash_params = HashManyParams {
            size:  message_size as u32,
            count: matrix.rows as u32,
        };
        let command_buffer = new_command_buffer(&runtime.queue)?;

        let encode_encoder = new_compute_encoder(&command_buffer)?;
        encode_encoder.setComputePipelineState(&runtime.encode_bytes_pipeline);
        set_buffer(&encode_encoder, 0, matrix.buffer.as_ref(), 0);
        set_buffer(&encode_encoder, 1, encoded.as_ref(), 0);
        set_bytes(&encode_encoder, 2, &encode_params);
        let encode_threads =
            runtime.threads_per_threadgroup(&runtime.encode_bytes_pipeline, total_elements);
        encode_encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  total_elements,
                height: 1,
                depth:  1,
            },
            encode_threads,
        );
        encode_encoder.endEncoding();

        let hash_encoder = new_compute_encoder(&command_buffer)?;
        hash_encoder.setComputePipelineState(&runtime.sha256_pipeline);
        set_buffer(&hash_encoder, 0, encoded.as_ref(), 0);
        set_buffer(&hash_encoder, 1, hashes.as_ref(), 0);
        set_bytes(&hash_encoder, 2, &hash_params);
        let hash_threads = runtime.threads_per_threadgroup(&runtime.sha256_pipeline, matrix.rows);
        hash_encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  matrix.rows,
                height: 1,
                depth:  1,
            },
            hash_threads,
        );
        hash_encoder.endEncoding();

        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)?;

        Ok(hashes)
    }

    pub(super) fn build_merkle_witness(
        &self,
        matrix_commit: &MatrixCommitConfig<Fr>,
        leaf_hashes: &PooledBuffer,
    ) -> Result<Arc<dyn WitnessTrait + Send + Sync>, String> {
        let runtime = self.runtime()?;
        let num_leaves = matrix_commit.num_rows();
        let leaf_capacity = 1usize << matrix_commit.merkle_tree.layers.len();
        let num_nodes = matrix_commit.merkle_tree.num_nodes();
        if leaf_capacity == 0 {
            return Err("invalid empty Merkle leaf capacity".into());
        }
        if num_nodes == 0 {
            return Err("invalid empty Merkle tree".into());
        }
        if num_leaves > leaf_capacity {
            return Err("Merkle config has fewer layers than leaves require".into());
        }
        if leaf_capacity > u32::MAX as usize {
            return Err("GPU Merkle launch exceeds current 32-bit grid limit".into());
        }

        let tree = runtime.pooled_buffer::<Hash>(num_nodes);
        let command_buffer = new_command_buffer(&runtime.queue)?;
        let blit = command_buffer.blitCommandEncoder().ok_or_else(|| {
            "Metal command buffer did not create a blit command encoder".to_string()
        })?;
        blit.fillBuffer_range_value(
            tree.as_ref(),
            NSRange::new(0, num_nodes * size_of::<Hash>()),
            0,
        );
        if num_leaves != 0 {
            unsafe {
                blit.copyFromBuffer_sourceOffset_toBuffer_destinationOffset_size(
                    leaf_hashes.as_ref(),
                    0,
                    tree.as_ref(),
                    0,
                    num_leaves * size_of::<Hash>(),
                );
            }
        }
        blit.endEncoding();

        let mut previous_offset = 0usize;
        let mut previous_len = leaf_capacity;
        for _ in matrix_commit.merkle_tree.layers.iter().rev() {
            let current_len = previous_len / 2;
            if current_len == 0 {
                break;
            }
            if current_len > u32::MAX as usize {
                return Err("GPU Merkle launch exceeds current 32-bit grid limit".into());
            }

            let params = HashManyParams {
                size:  64,
                count: current_len as u32,
            };
            let current_offset = previous_offset + previous_len;
            let encoder = new_compute_encoder(&command_buffer)?;
            encoder.setComputePipelineState(&runtime.sha256_pipeline);
            set_buffer(
                &encoder,
                0,
                tree.as_ref(),
                previous_offset * size_of::<Hash>(),
            );
            set_buffer(
                &encoder,
                1,
                tree.as_ref(),
                current_offset * size_of::<Hash>(),
            );
            set_bytes(&encoder, 2, &params);
            let threads = runtime.threads_per_threadgroup(&runtime.sha256_pipeline, current_len);
            encoder.dispatchThreads_threadsPerThreadgroup(
                MTLSize {
                    width:  current_len,
                    height: 1,
                    depth:  1,
                },
                threads,
            );
            encoder.endEncoding();
            previous_offset = current_offset;
            previous_len = current_len;
        }

        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)?;

        let root = runtime.buffer_slice::<Hash>(tree.as_ref(), num_nodes)[num_nodes - 1];

        Ok(Arc::new(DeviceMerkleWitness {
            num_nodes,
            root,
            buffer: tree,
        }))
    }
}

impl WitnessTrait for DeviceMerkleWitness {
    fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    fn read_nodes(&self, indices: &[usize]) -> Vec<Hash> {
        if indices.is_empty() {
            return Vec::new();
        }
        assert!(
            self.num_nodes <= u32::MAX as usize,
            "Metal Merkle witness exceeds current 32-bit gather limit"
        );
        let total_bytes = indices
            .len()
            .checked_mul(size_of::<Hash>())
            .expect("Merkle node gather byte count overflow");
        assert!(
            total_bytes <= u32::MAX as usize,
            "Metal Merkle gather exceeds current 32-bit grid limit"
        );

        let indices: Vec<u32> = indices
            .iter()
            .map(|&index| {
                assert!(index < self.num_nodes, "Merkle node index out of bounds");
                index as u32
            })
            .collect();
        let runtime = crate::ntt::MetalBn254Ntt
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let index_buffer = runtime.buffer_with_data(&indices);
        let staging = runtime.pooled_bytes(total_bytes);
        let params = GatherHashesParams {
            num_nodes: self.num_nodes as u32,
            count:     indices.len() as u32,
            _pad0:     0,
            _pad1:     0,
        };

        let command_buffer = new_command_buffer(&runtime.queue)
            .unwrap_or_else(|err| panic!("Metal Merkle gather command buffer failed: {err}"));
        let encoder = new_compute_encoder(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal Merkle gather encoder failed: {err}"));
        encoder.setComputePipelineState(&runtime.gather_hashes_pipeline);
        set_buffer(&encoder, 0, self.buffer.as_ref(), 0);
        set_buffer(&encoder, 1, &index_buffer, 0);
        set_buffer(&encoder, 2, staging.as_ref(), 0);
        set_bytes(&encoder, 3, &params);
        let threads = runtime.threads_per_threadgroup(&runtime.gather_hashes_pipeline, total_bytes);
        encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  total_bytes,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.endEncoding();
        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal Merkle gather failed: {err}"));

        let gathered = runtime.buffer_slice::<Hash>(staging.as_ref(), indices.len());
        let mut out = Vec::with_capacity(gathered.len());
        for node in gathered {
            out.push(*node);
        }
        out
    }
}

impl std::fmt::Debug for DeviceRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRows")
            .field("rows", &self.rows)
            .field("cols", &self.cols)
            .finish()
    }
}

impl MatrixRows<Fr> for DeviceRows {
    fn num_rows(&self) -> usize {
        self.rows
    }

    fn num_cols(&self) -> usize {
        self.cols
    }

    fn read_rows(&self, indices: &[usize]) -> Vec<Fr> {
        if indices.is_empty() {
            return Vec::new();
        }
        assert!(
            self.rows <= u32::MAX as usize && self.cols <= u32::MAX as usize,
            "Metal matrix exceeds current 32-bit gather limit"
        );
        let total_elements = indices
            .len()
            .checked_mul(self.cols)
            .expect("matrix row gather element count overflow");
        assert!(
            total_elements <= u32::MAX as usize,
            "Metal matrix row gather exceeds current 32-bit grid limit"
        );

        let indices: Vec<u32> = indices
            .iter()
            .map(|&row| {
                assert!(row < self.rows, "row index out of bounds");
                row as u32
            })
            .collect();
        if self.cols == 0 {
            return Vec::new();
        }
        let runtime = crate::ntt::MetalBn254Ntt
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let index_buffer = runtime.buffer_with_data(&indices);
        let staging = runtime.pooled_buffer::<GpuField>(total_elements);
        let params = GatherRowsParams {
            rows:  self.rows as u32,
            cols:  self.cols as u32,
            count: indices.len() as u32,
            _pad0: 0,
        };

        let command_buffer = new_command_buffer(&runtime.queue)
            .unwrap_or_else(|err| panic!("Metal matrix row gather command buffer failed: {err}"));
        let encoder = new_compute_encoder(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal matrix row gather encoder failed: {err}"));
        encoder.setComputePipelineState(&runtime.gather_rows_pipeline);
        set_buffer(&encoder, 0, self.buffer.as_ref(), 0);
        set_buffer(&encoder, 1, &index_buffer, 0);
        set_buffer(&encoder, 2, staging.as_ref(), 0);
        set_bytes(&encoder, 3, &params);
        let threads =
            runtime.threads_per_threadgroup(&runtime.gather_rows_pipeline, total_elements);
        encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  total_elements,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.endEncoding();
        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal matrix row gather failed: {err}"));

        runtime
            .buffer_slice::<GpuField>(staging.as_ref(), total_elements)
            .iter()
            .copied()
            .map(gpu_to_fr)
            .collect()
    }
}

impl std::fmt::Debug for DeviceMerkleWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceMerkleWitness")
            .field("num_nodes", &self.num_nodes)
            .field("root", &self.root)
            .finish()
    }
}
