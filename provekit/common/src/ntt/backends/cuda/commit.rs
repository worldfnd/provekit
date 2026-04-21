use {
    super::{
        engine::PooledBuffer,
        field::gpu_to_fr,
        types::{
            DeviceMatrix, DeviceMerkleWitness, DeviceRows, EncodeFieldBytesParams, GpuField,
            HashManyParams,
        },
        CudaBn254Ntt,
    },
    ark_bn254::Fr,
    cudarc::driver::PushKernelArg,
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

impl IrsCommitter<Fr> for CudaBn254Ntt {
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

impl CudaBn254Ntt {
    /// Hash every row of `matrix` with SHA-256 on the GPU. Returns a pooled
    /// device buffer holding `matrix.rows * 32` bytes (one digest per row).
    pub(super) fn hash_rows_to_buffer(
        &self,
        matrix: &DeviceMatrix,
    ) -> Result<PooledBuffer, String> {
        let runtime = self.runtime()?;
        if matrix.rows == 0 {
            return Ok(runtime.pooled_buffer::<Hash>(0));
        }

        let total_elements = matrix.rows * matrix.cols;
        let total_bytes = total_elements * Fr::encoded_size();
        let message_size = matrix.cols * Fr::encoded_size();
        if total_elements > u32::MAX as usize || message_size > u32::MAX as usize {
            return Err("GPU hash launch exceeds current 32-bit grid limit".into());
        }

        // Encoded canonical bytes (rows × cols × 32 bytes), in natural row
        // order (the encode kernel applies the bit-reversal of the row
        // index when reading from `matrix.buffer`).
        let encoded = runtime.pooled_bytes(total_bytes);
        let hashes = runtime.pooled_buffer::<Hash>(matrix.rows);

        let encode_params = EncodeFieldBytesParams {
            rows: matrix.rows as u32,
            cols: matrix.cols as u32,
        };
        {
            let cfg = runtime.launch_cfg_1d(total_elements);
            // SAFETY: kernel signature matches; ranges in-bounds.
            unsafe {
                runtime
                    .stream
                    .launch_builder(&runtime.encode_bytes_function)
                    .arg(matrix.buffer.slice())
                    .arg(encoded.slice())
                    .arg(&encode_params)
                    .launch(cfg)
            }
            .map_err(|e| format!("launch encode_field_rows_le: {e:?}"))?;
        }

        let hash_params = HashManyParams {
            size:  message_size as u32,
            count: matrix.rows as u32,
        };
        {
            let cfg = runtime.launch_cfg_1d(matrix.rows);
            // SAFETY: kernel signature matches; ranges in-bounds.
            unsafe {
                runtime
                    .stream
                    .launch_builder(&runtime.sha256_function)
                    .arg(encoded.slice())
                    .arg(hashes.slice())
                    .arg(&hash_params)
                    .launch(cfg)
            }
            .map_err(|e| format!("launch sha256_many (leaf): {e:?}"))?;
        }

        runtime.synchronize()?;
        Ok(hashes)
    }

    /// Build the Merkle tree on device by repeatedly hashing pairs of nodes.
    /// `leaf_hashes` is the (rows × 32 bytes) buffer produced by
    /// [`hash_rows_to_buffer`]. The resulting `DeviceMerkleWitness` owns a
    /// pooled tree buffer; `read_nodes` lazily downloads requested nodes.
    pub(super) fn build_merkle_witness(
        &self,
        matrix_commit: &MatrixCommitConfig<Fr>,
        leaf_hashes: &PooledBuffer,
    ) -> Result<Arc<dyn WitnessTrait>, String> {
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
        runtime.memset_zeros(&tree, 0, num_nodes * size_of::<Hash>())?;
        if num_leaves != 0 {
            runtime.memcpy_dtod_bytes(
                &tree,
                0,
                leaf_hashes,
                0,
                num_leaves * size_of::<Hash>(),
            )?;
        }

        // Walk the layers from leaf to root, each iteration hashing the
        // 2^k current-layer nodes into 2^(k-1) parent-layer nodes.
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
            let prev_byte_off = previous_offset * size_of::<Hash>();
            let curr_byte_off = (previous_offset + previous_len) * size_of::<Hash>();

            // The sha256_many kernel takes input/output by raw byte
            // pointer; cudarc forwards the device pointer plus offset via a
            // byte-offset CudaView.
            let input_view = tree
                .slice()
                .try_slice(prev_byte_off..prev_byte_off + previous_len * size_of::<Hash>())
                .ok_or_else(|| "merkle: input view oob".to_string())?;
            let output_view = tree
                .slice()
                .try_slice(curr_byte_off..curr_byte_off + current_len * size_of::<Hash>())
                .ok_or_else(|| "merkle: output view oob".to_string())?;
            let cfg = runtime.launch_cfg_1d(current_len);
            // SAFETY: kernel reads from `input_view` and writes to
            // `output_view`; the two ranges are disjoint regions of the
            // tree buffer (parent layer comes after child layer in memory).
            unsafe {
                runtime
                    .stream
                    .launch_builder(&runtime.sha256_function)
                    .arg(&input_view)
                    .arg(&output_view)
                    .arg(&params)
                    .launch(cfg)
            }
            .map_err(|e| format!("launch sha256_many (merkle): {e:?}"))?;

            previous_offset += previous_len;
            previous_len = current_len;
        }

        runtime.synchronize()?;

        // Read just the root (last node) back to surface it via
        // `IrsCommitArtifact.root`.
        let mut root_bytes = [0u8; size_of::<Hash>()];
        runtime.download_bytes(&tree, (num_nodes - 1) * size_of::<Hash>(), &mut root_bytes)?;
        let mut root = Hash::default();
        root.0.copy_from_slice(&root_bytes);

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
        let runtime = match crate::ntt::CudaBn254Ntt::default().runtime() {
            Ok(r) => Arc::clone(r),
            Err(err) => panic!("CUDA runtime unavailable: {err}"),
        };
        let mut out = Vec::with_capacity(indices.len());
        for &index in indices {
            assert!(index < self.num_nodes, "Merkle node index out of bounds");
            let mut bytes = [0u8; size_of::<Hash>()];
            runtime
                .download_bytes(&self.buffer, index * size_of::<Hash>(), &mut bytes)
                .unwrap_or_else(|err| panic!("CUDA Merkle node download failed: {err}"));
            let mut hash = Hash::default();
            hash.0.copy_from_slice(&bytes);
            out.push(hash);
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

    /// Lazily download just the requested rows from the device buffer,
    /// applying the bit-reversal of the codeword index so that index `i`
    /// in `indices` corresponds to natural codeword position `i`.
    fn read_rows(&self, indices: &[usize]) -> Vec<Fr> {
        let runtime = match crate::ntt::CudaBn254Ntt::default().runtime() {
            Ok(r) => Arc::clone(r),
            Err(err) => panic!("CUDA runtime unavailable: {err}"),
        };
        let cols = self.cols;
        let row_bytes = cols * size_of::<GpuField>();
        let mut out: Vec<Fr> = Vec::with_capacity(indices.len() * cols);
        let mut staging: Vec<GpuField> = vec![GpuField::default(); cols];
        for &row in indices {
            assert!(row < self.rows, "row index out of bounds");
            let src_row = reverse_bit_index(row, self.rows);
            // SAFETY: GpuField is plain repr(C) bytes; staging.len() == cols.
            unsafe {
                runtime
                    .download_into::<GpuField>(&self.buffer, src_row * row_bytes, &mut staging)
                    .unwrap_or_else(|err| panic!("CUDA matrix row download failed: {err}"));
            }
            out.extend(staging.iter().copied().map(gpu_to_fr));
        }
        out
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

fn reverse_bit_index(index: usize, codeword_length: usize) -> usize {
    let bits = usize::BITS - (codeword_length - 1).leading_zeros();
    if bits == 0 {
        index
    } else {
        index.reverse_bits() >> (usize::BITS - bits)
    }
}
