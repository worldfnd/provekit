use {
    super::{
        engine::{
            check_command_buffer, new_command_buffer, new_compute_encoder, set_buffer, set_bytes,
            Buffer, ComputeCommandEncoder, PooledBuffer,
        },
        field::{fr_to_gpu, gpu_to_fr},
        types::{
            BeqAccumParams, EqExpandParams, EqInitParams, FoldParams, GammaEvalParams,
            GammaReduceParams, GpuField, ReduceParams, SumcheckParams, UnivariateAccumParams,
            UnivariateEvalParams, VectorLenParams,
        },
        MetalBn254Ntt,
    },
    ark_bn254::Fr,
    ark_ff::{AdditiveGroup, Field},
    objc2_metal::{MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLSize},
    std::{any::Any, mem::size_of, time::Instant},
    whir::protocols::{
        irs_commit::IrsCommitArtifact,
        matrix_commit::Config as MatrixCommitConfig,
        whir_accelerator::{DeviceVector, WhirProverAccelerator},
    },
};

const REDUCE_CHUNK: usize = 256;

pub struct MetalDeviceVector {
    len:    usize,
    buffer: PooledBuffer,
}

impl MetalDeviceVector {
    fn new(len: usize, buffer: PooledBuffer) -> Self {
        Self { len, buffer }
    }
}

impl DeviceVector<Fr> for MetalDeviceVector {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl MetalBn254Ntt {
    fn metal_vector<'a>(&self, vector: &'a dyn DeviceVector<Fr>) -> &'a MetalDeviceVector {
        vector
            .as_any()
            .downcast_ref::<MetalDeviceVector>()
            .expect("device vector was not created by the Metal WHIR accelerator")
    }

    fn metal_vector_mut<'a>(
        &self,
        vector: &'a mut dyn DeviceVector<Fr>,
    ) -> &'a mut MetalDeviceVector {
        vector
            .as_any_mut()
            .downcast_mut::<MetalDeviceVector>()
            .expect("device vector was not created by the Metal WHIR accelerator")
    }

    fn gpu_fields(&self, values: &[Fr]) -> Vec<GpuField> {
        values.iter().copied().map(fr_to_gpu).collect()
    }

    fn launch_1d(
        &self,
        pipeline: &BufferlessPipeline,
        work_items: usize,
        encode: impl FnOnce(&ComputeCommandEncoder),
    ) {
        if work_items == 0 {
            return;
        }
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let command_buffer = new_command_buffer(&runtime.queue)
            .unwrap_or_else(|err| panic!("Metal command buffer failed: {err}"));
        let encoder = new_compute_encoder(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal compute encoder failed: {err}"));
        encoder.setComputePipelineState(pipeline.get(&runtime));
        encode(&encoder);
        let threads = runtime.threads_per_threadgroup(pipeline.get(&runtime), work_items);
        encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  work_items,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.endEncoding();
        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal WHIR kernel failed: {err}"));
    }

    fn reduce_sum_buffer(&self, input: &Buffer, len: usize) -> Fr {
        if len == 0 {
            return Fr::ZERO;
        }
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let mut owned_buffers = Vec::new();
        let mut current_len = len;
        let mut current: &Buffer = input;
        while current_len > 1 {
            let output_len = current_len.div_ceil(REDUCE_CHUNK);
            let output = runtime.pooled_buffer::<GpuField>(output_len);
            let params = ReduceParams {
                len:              current_len as u32,
                values_per_chunk: REDUCE_CHUNK as u32,
                _pad0:            0,
                _pad1:            0,
            };
            let command_buffer = new_command_buffer(&runtime.queue)
                .unwrap_or_else(|err| panic!("Metal reduce command buffer failed: {err}"));
            let encoder = new_compute_encoder(&command_buffer)
                .unwrap_or_else(|err| panic!("Metal reduce encoder failed: {err}"));
            encoder.setComputePipelineState(&runtime.reduce_sum_pipeline);
            set_buffer(&encoder, 0, current, 0);
            set_buffer(&encoder, 1, output.as_ref(), 0);
            set_bytes(&encoder, 2, &params);
            let threads = runtime.threads_per_threadgroup(&runtime.reduce_sum_pipeline, output_len);
            encoder.dispatchThreads_threadsPerThreadgroup(
                MTLSize {
                    width:  output_len,
                    height: 1,
                    depth:  1,
                },
                threads,
            );
            encoder.endEncoding();
            command_buffer.commit();
            command_buffer.waitUntilCompleted();
            check_command_buffer(&command_buffer)
                .unwrap_or_else(|err| panic!("Metal reduce failed: {err}"));
            owned_buffers.push(output);
            current = owned_buffers.last().unwrap().as_ref();
            current_len = output_len;
        }
        gpu_to_fr(runtime.buffer_slice::<GpuField>(current, 1)[0])
    }

    fn reduce_sum_pair_buffers(
        &self,
        input_c0: &Buffer,
        input_c2: &Buffer,
        len: usize,
    ) -> (Fr, Fr) {
        if len == 0 {
            return (Fr::ZERO, Fr::ZERO);
        }
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        if len == 1 {
            return (
                gpu_to_fr(runtime.buffer_slice::<GpuField>(input_c0, 1)[0]),
                gpu_to_fr(runtime.buffer_slice::<GpuField>(input_c2, 1)[0]),
            );
        }

        let mut owned_buffers = Vec::new();
        let mut current_len = len;
        let mut current_c0: &Buffer = input_c0;
        let mut current_c2: &Buffer = input_c2;
        while current_len > 1 {
            let output_len = current_len.div_ceil(REDUCE_CHUNK);
            let params = ReduceParams {
                len:              current_len as u32,
                values_per_chunk: REDUCE_CHUNK as u32,
                _pad0:            0,
                _pad1:            0,
            };
            let command_buffer = new_command_buffer(&runtime.queue)
                .unwrap_or_else(|err| panic!("Metal pair reduce command buffer failed: {err}"));
            let encoder = new_compute_encoder(&command_buffer)
                .unwrap_or_else(|err| panic!("Metal pair reduce encoder failed: {err}"));
            encoder.setComputePipelineState(&runtime.reduce_pair_sum_pipeline);
            set_buffer(&encoder, 0, current_c0, 0);
            set_buffer(&encoder, 1, current_c2, 0);

            let pair_output;
            let output_c0;
            let output_c2;
            if output_len == 1 {
                pair_output = runtime.pooled_buffer::<GpuField>(2);
                set_buffer(&encoder, 2, pair_output.as_ref(), 0);
                set_buffer(&encoder, 3, pair_output.as_ref(), size_of::<GpuField>());
                set_bytes(&encoder, 4, &params);
                let threads =
                    runtime.threads_per_threadgroup(&runtime.reduce_pair_sum_pipeline, output_len);
                encoder.dispatchThreads_threadsPerThreadgroup(
                    MTLSize {
                        width:  output_len,
                        height: 1,
                        depth:  1,
                    },
                    threads,
                );
                encoder.endEncoding();
                command_buffer.commit();
                command_buffer.waitUntilCompleted();
                check_command_buffer(&command_buffer)
                    .unwrap_or_else(|err| panic!("Metal pair reduce failed: {err}"));
                let values = runtime.buffer_slice::<GpuField>(pair_output.as_ref(), 2);
                return (gpu_to_fr(values[0]), gpu_to_fr(values[1]));
            } else {
                output_c0 = runtime.pooled_buffer::<GpuField>(output_len);
                output_c2 = runtime.pooled_buffer::<GpuField>(output_len);
                set_buffer(&encoder, 2, output_c0.as_ref(), 0);
                set_buffer(&encoder, 3, output_c2.as_ref(), 0);
                set_bytes(&encoder, 4, &params);
                let threads =
                    runtime.threads_per_threadgroup(&runtime.reduce_pair_sum_pipeline, output_len);
                encoder.dispatchThreads_threadsPerThreadgroup(
                    MTLSize {
                        width:  output_len,
                        height: 1,
                        depth:  1,
                    },
                    threads,
                );
                encoder.endEncoding();
                command_buffer.commit();
                command_buffer.waitUntilCompleted();
                check_command_buffer(&command_buffer)
                    .unwrap_or_else(|err| panic!("Metal pair reduce failed: {err}"));
                owned_buffers.push((output_c0, output_c2));
                let (last_c0, last_c2) = owned_buffers.last().unwrap();
                current_c0 = last_c0.as_ref();
                current_c2 = last_c2.as_ref();
                current_len = output_len;
            }
        }

        unreachable!("pair reduction loop returns when output_len reaches one")
    }
}

struct BufferlessPipeline(
    for<'a> fn(&'a super::engine::MetalRuntime) -> &'a super::engine::ComputePipelineState,
);

impl BufferlessPipeline {
    fn get<'a>(
        &self,
        runtime: &'a super::engine::MetalRuntime,
    ) -> &'a super::engine::ComputePipelineState {
        self.0(runtime)
    }
}

impl WhirProverAccelerator<Fr> for MetalBn254Ntt {
    fn upload(&self, values: &[Fr]) -> Box<dyn DeviceVector<Fr>> {
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let buffer = runtime.pooled_buffer::<GpuField>(values.len());
        runtime
            .buffer_slice_mut::<GpuField>(buffer.as_ref(), values.len())
            .copy_from_slice(&self.gpu_fields(values));
        Box::new(MetalDeviceVector::new(values.len(), buffer))
    }

    fn upload_zeroes(&self, len: usize) -> Box<dyn DeviceVector<Fr>> {
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let buffer = runtime.pooled_buffer::<GpuField>(len);
        runtime.zero_buffer::<GpuField>(buffer.as_ref(), len);
        Box::new(MetalDeviceVector::new(len, buffer))
    }

    fn download(&self, vector: &dyn DeviceVector<Fr>) -> Vec<Fr> {
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let vector = self.metal_vector(vector);
        runtime
            .buffer_slice::<GpuField>(vector.buffer.as_ref(), vector.len)
            .iter()
            .copied()
            .map(gpu_to_fr)
            .collect()
    }

    fn add_assign_scaled_slice(
        &self,
        accumulator: &mut dyn DeviceVector<Fr>,
        scalar: Fr,
        values: &[Fr],
    ) {
        let accumulator = self.metal_vector_mut(accumulator);
        assert_eq!(accumulator.len, values.len());
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let values = runtime.buffer_with_data(&self.gpu_fields(values));
        let scalar = fr_to_gpu(scalar);
        let params = VectorLenParams {
            len:   accumulator.len as u32,
            _pad0: 0,
            _pad1: 0,
            _pad2: 0,
        };
        self.launch_1d(
            &BufferlessPipeline(|runtime| &runtime.vector_add_scaled_pipeline),
            accumulator.len,
            |encoder| {
                set_buffer(encoder, 0, accumulator.buffer.as_ref(), 0);
                set_buffer(encoder, 1, &values, 0);
                set_bytes(encoder, 2, &scalar);
                set_bytes(encoder, 3, &params);
            },
        );
    }

    fn add_assign_scaled_device_vector(
        &self,
        accumulator: &mut dyn DeviceVector<Fr>,
        scalar: Fr,
        values: &dyn DeviceVector<Fr>,
    ) {
        let values = self.metal_vector(values);
        let accumulator = self.metal_vector_mut(accumulator);
        assert_eq!(accumulator.len, values.len);
        let scalar = fr_to_gpu(scalar);
        let params = VectorLenParams {
            len:   accumulator.len as u32,
            _pad0: 0,
            _pad1: 0,
            _pad2: 0,
        };
        self.launch_1d(
            &BufferlessPipeline(|runtime| &runtime.vector_add_scaled_pipeline),
            accumulator.len,
            |encoder| {
                set_buffer(encoder, 0, accumulator.buffer.as_ref(), 0);
                set_buffer(encoder, 1, values.buffer.as_ref(), 0);
                set_bytes(encoder, 2, &scalar);
                set_bytes(encoder, 3, &params);
            },
        );
    }

    fn accumulate_univariate_evaluations(
        &self,
        accumulator: &mut dyn DeviceVector<Fr>,
        points: &[Fr],
        scalars: &[Fr],
    ) {
        assert_eq!(points.len(), scalars.len());
        if points.is_empty() {
            return;
        }
        let accumulator = self.metal_vector_mut(accumulator);
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let point_count = points.len();
        let points = runtime.buffer_with_data(&self.gpu_fields(points));
        let scalars = runtime.buffer_with_data(&self.gpu_fields(scalars));
        let params = UnivariateAccumParams {
            len:   accumulator.len as u32,
            count: point_count as u32,
            _pad0: 0,
            _pad1: 0,
        };
        self.launch_1d(
            &BufferlessPipeline(|runtime| &runtime.univariate_accum_pipeline),
            accumulator.len,
            |encoder| {
                set_buffer(encoder, 0, accumulator.buffer.as_ref(), 0);
                set_buffer(encoder, 1, &points, 0);
                set_buffer(encoder, 2, &scalars, 0);
                set_bytes(encoder, 3, &params);
            },
        );
    }

    fn dot(&self, a: &dyn DeviceVector<Fr>, b: &dyn DeviceVector<Fr>) -> Fr {
        let a = self.metal_vector(a);
        let b = self.metal_vector(b);
        assert_eq!(a.len, b.len);
        if a.len == 0 {
            return Fr::ZERO;
        }
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let partial_count = a.len.div_ceil(REDUCE_CHUNK);
        let partials = runtime.pooled_buffer::<GpuField>(partial_count);
        let params = ReduceParams {
            len:              a.len as u32,
            values_per_chunk: REDUCE_CHUNK as u32,
            _pad0:            0,
            _pad1:            0,
        };
        let command_buffer = new_command_buffer(&runtime.queue)
            .unwrap_or_else(|err| panic!("Metal dot command buffer failed: {err}"));
        let encoder = new_compute_encoder(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal dot encoder failed: {err}"));
        encoder.setComputePipelineState(&runtime.dot_partials_pipeline);
        set_buffer(&encoder, 0, a.buffer.as_ref(), 0);
        set_buffer(&encoder, 1, b.buffer.as_ref(), 0);
        set_buffer(&encoder, 2, partials.as_ref(), 0);
        set_bytes(&encoder, 3, &params);
        let threads =
            runtime.threads_per_threadgroup(&runtime.dot_partials_pipeline, partial_count);
        encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  partial_count,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.endEncoding();
        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal dot product failed: {err}"));
        self.reduce_sum_buffer(partials.as_ref(), partial_count)
    }

    fn fold(&self, vector: &mut dyn DeviceVector<Fr>, weight: Fr) {
        let vector = self.metal_vector_mut(vector);
        if vector.len <= 1 {
            return;
        }
        let half = vector.len.next_power_of_two() >> 1;
        let weight = fr_to_gpu(weight);
        let params = FoldParams {
            len:        vector.len as u32,
            half_width: half as u32,
            _pad0:      0,
            _pad1:      0,
        };
        self.launch_1d(
            &BufferlessPipeline(|runtime| &runtime.fold_vector_pipeline),
            half,
            |encoder| {
                set_buffer(encoder, 0, vector.buffer.as_ref(), 0);
                set_bytes(encoder, 1, &weight);
                set_bytes(encoder, 2, &params);
            },
        );
        vector.len = half;
    }

    fn sumcheck_polynomial(&self, a: &dyn DeviceVector<Fr>, b: &dyn DeviceVector<Fr>) -> (Fr, Fr) {
        let timing = std::env::var_os("PROVEKIT_WHIR_GPU_TIMING").is_some();
        let total_start = timing.then(Instant::now);
        let a = self.metal_vector(a);
        let b = self.metal_vector(b);
        assert_eq!(a.len, b.len);
        if a.len == 0 {
            return (Fr::ZERO, Fr::ZERO);
        }
        if a.len == 1 {
            let value = self.download(a)[0] * self.download(b)[0];
            return (value, Fr::ZERO);
        }
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let half = a.len.next_power_of_two() >> 1;
        let pair_count = half;
        let partial_count = pair_count.div_ceil(REDUCE_CHUNK);
        let partial_c0 = runtime.pooled_buffer::<GpuField>(partial_count);
        let partial_c2 = runtime.pooled_buffer::<GpuField>(partial_count);
        let params = SumcheckParams {
            len:               a.len as u32,
            half_width:        half as u32,
            pair_count:        pair_count as u32,
            pairs_per_partial: REDUCE_CHUNK as u32,
        };
        let partials_start = timing.then(Instant::now);
        let command_buffer = new_command_buffer(&runtime.queue)
            .unwrap_or_else(|err| panic!("Metal sumcheck command buffer failed: {err}"));
        let encoder = new_compute_encoder(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal sumcheck encoder failed: {err}"));
        encoder.setComputePipelineState(&runtime.sumcheck_partials_pipeline);
        set_buffer(&encoder, 0, a.buffer.as_ref(), 0);
        set_buffer(&encoder, 1, b.buffer.as_ref(), 0);
        set_buffer(&encoder, 2, partial_c0.as_ref(), 0);
        set_buffer(&encoder, 3, partial_c2.as_ref(), 0);
        set_bytes(&encoder, 4, &params);
        let threads =
            runtime.threads_per_threadgroup(&runtime.sumcheck_partials_pipeline, partial_count);
        encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  partial_count,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.endEncoding();
        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal sumcheck polynomial failed: {err}"));
        let partials_us = partials_start.map_or(0, |start| start.elapsed().as_micros());

        let reduce_start = timing.then(Instant::now);
        let (c0, c2) =
            self.reduce_sum_pair_buffers(partial_c0.as_ref(), partial_c2.as_ref(), partial_count);
        let reduce_us = reduce_start.map_or(0, |start| start.elapsed().as_micros());

        if let Some(total_start) = total_start {
            eprintln!(
                "METAL_WHIR_SUMCHECK len={} partial_count={} partials_us={} reduce_pair_us={} \
                 total_us={}",
                a.len,
                partial_count,
                partials_us,
                reduce_us,
                total_start.elapsed().as_micros(),
            );
        }

        (c0, c2)
    }

    fn evaluate_univariate_many(&self, vector: &dyn DeviceVector<Fr>, points: &[Fr]) -> Vec<Fr> {
        if points.is_empty() {
            return Vec::new();
        }
        let vector = self.metal_vector(vector);
        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));
        let points_gpu = runtime.buffer_with_data(&self.gpu_fields(points));
        let partial_count = vector.len.div_ceil(REDUCE_CHUNK).max(1);
        let total_partials = points.len() * partial_count;
        let partials = runtime.pooled_buffer::<GpuField>(total_partials);
        let params = UnivariateEvalParams {
            len:              vector.len as u32,
            point_count:      points.len() as u32,
            values_per_chunk: REDUCE_CHUNK as u32,
            partial_count:    partial_count as u32,
        };
        let command_buffer = new_command_buffer(&runtime.queue)
            .unwrap_or_else(|err| panic!("Metal univariate eval command buffer failed: {err}"));
        let encoder = new_compute_encoder(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal univariate eval encoder failed: {err}"));
        encoder.setComputePipelineState(&runtime.univariate_eval_pipeline);
        set_buffer(&encoder, 0, vector.buffer.as_ref(), 0);
        set_buffer(&encoder, 1, &points_gpu, 0);
        set_buffer(&encoder, 2, partials.as_ref(), 0);
        set_bytes(&encoder, 3, &params);
        let threads =
            runtime.threads_per_threadgroup(&runtime.univariate_eval_pipeline, total_partials);
        encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width:  total_partials,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.endEncoding();
        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        check_command_buffer(&command_buffer)
            .unwrap_or_else(|err| panic!("Metal univariate evaluation failed: {err}"));

        runtime
            .buffer_slice::<GpuField>(partials.as_ref(), total_partials)
            .chunks_exact(partial_count)
            .map(|partials| partials.iter().copied().map(gpu_to_fr).sum())
            .collect()
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate_gamma_block(
        &self,
        blinding_vectors: &dyn DeviceVector<Fr>,
        gammas: &[Fr],
        masking_challenge: Fr,
        blinding_challenge: Fr,
        tau2: Fr,
        num_polynomials: usize,
        num_witness_variables: usize,
        num_blinding_variables: usize,
    ) -> Option<(Vec<Fr>, Box<dyn DeviceVector<Fr>>)> {
        let timing = std::env::var_os("PROVEKIT_WHIR_GPU_TIMING").is_some();
        let total_start = timing.then(Instant::now);
        let packed_vectors = self.metal_vector(blinding_vectors);
        let half_size = 1usize.checked_shl(num_blinding_variables as u32)?;
        let weight_size = half_size.checked_mul(2)?;
        let vectors_per_polynomial = num_witness_variables.checked_add(1)?;
        let vector_count = num_polynomials.checked_mul(vectors_per_polynomial)?;
        assert_eq!(packed_vectors.len, vector_count * weight_size);

        let runtime = self
            .runtime()
            .unwrap_or_else(|err| panic!("Metal runtime unavailable: {err}"));

        if gammas.is_empty() {
            let beq = runtime.pooled_buffer::<GpuField>(weight_size);
            runtime.zero_buffer::<GpuField>(beq.as_ref(), weight_size);
            return Some((
                Vec::new(),
                Box::new(MetalDeviceVector::new(weight_size, beq)),
            ));
        }

        let gamma_powers = {
            let mut powers = Vec::with_capacity(gammas.len() * num_blinding_variables);
            for &gamma in gammas {
                let mut power = gamma;
                for _ in 0..num_blinding_variables {
                    powers.push(power);
                    power = power.square();
                }
            }
            runtime.buffer_with_data(&self.gpu_fields(&powers))
        };
        let tau_powers = {
            let mut powers = Vec::with_capacity(gammas.len());
            let mut power = Fr::ONE;
            for _ in gammas {
                powers.push(power);
                power *= tau2;
            }
            runtime.buffer_with_data(&self.gpu_fields(&powers))
        };

        let eq_a = runtime.pooled_buffer::<GpuField>(gammas.len() * half_size);
        let eq_b = runtime.pooled_buffer::<GpuField>(gammas.len() * half_size);
        let eq_start = timing.then(Instant::now);
        {
            let command_buffer = new_command_buffer(&runtime.queue)
                .unwrap_or_else(|err| panic!("Metal eq weights command buffer failed: {err}"));
            let encoder = new_compute_encoder(&command_buffer)
                .unwrap_or_else(|err| panic!("Metal eq weights encoder failed: {err}"));

            let init_params = EqInitParams {
                gamma_count: gammas.len() as u32,
                stride:      half_size as u32,
                _pad0:       0,
                _pad1:       0,
            };
            encoder.setComputePipelineState(&runtime.eq_weights_init_pipeline);
            set_buffer(&encoder, 0, eq_a.as_ref(), 0);
            set_bytes(&encoder, 1, &init_params);
            let threads =
                runtime.threads_per_threadgroup(&runtime.eq_weights_init_pipeline, gammas.len());
            encoder.dispatchThreads_threadsPerThreadgroup(
                MTLSize {
                    width:  gammas.len(),
                    height: 1,
                    depth:  1,
                },
                threads,
            );

            for stage in 0..num_blinding_variables {
                let stage_width = 1usize << stage;
                let work_items = gammas.len() * stage_width;
                let (input, output) = if stage % 2 == 0 {
                    (eq_a.as_ref(), eq_b.as_ref())
                } else {
                    (eq_b.as_ref(), eq_a.as_ref())
                };
                let params = EqExpandParams {
                    gamma_count:  gammas.len() as u32,
                    stride:       half_size as u32,
                    stage_width:  stage_width as u32,
                    stage:        stage as u32,
                    power_stride: num_blinding_variables as u32,
                    _pad0:        0,
                    _pad1:        0,
                    _pad2:        0,
                };
                encoder.setComputePipelineState(&runtime.eq_weights_expand_pipeline);
                set_buffer(&encoder, 0, input, 0);
                set_buffer(&encoder, 1, output, 0);
                set_buffer(&encoder, 2, &gamma_powers, 0);
                set_bytes(&encoder, 3, &params);
                let threads = runtime
                    .threads_per_threadgroup(&runtime.eq_weights_expand_pipeline, work_items);
                encoder.dispatchThreads_threadsPerThreadgroup(
                    MTLSize {
                        width:  work_items,
                        height: 1,
                        depth:  1,
                    },
                    threads,
                );
            }

            encoder.endEncoding();
            command_buffer.commit();
            command_buffer.waitUntilCompleted();
            check_command_buffer(&command_buffer)
                .unwrap_or_else(|err| panic!("Metal eq weights failed: {err}"));
        }
        let eq_us = eq_start.map_or(0, |start| start.elapsed().as_micros());
        let eq_half = if num_blinding_variables % 2 == 0 {
            eq_a.as_ref()
        } else {
            eq_b.as_ref()
        };

        let beq = runtime.pooled_buffer::<GpuField>(weight_size);
        let masking_challenge_gpu = fr_to_gpu(masking_challenge);
        let beq_start = timing.then(Instant::now);
        let beq_params = BeqAccumParams {
            half_size:   half_size as u32,
            gamma_count: gammas.len() as u32,
            _pad0:       0,
            _pad1:       0,
        };
        self.launch_1d(
            &BufferlessPipeline(|runtime| &runtime.beq_accumulate_pipeline),
            half_size,
            |encoder| {
                set_buffer(encoder, 0, eq_half, 0);
                set_buffer(encoder, 1, &tau_powers, 0);
                set_buffer(encoder, 2, beq.as_ref(), 0);
                set_bytes(encoder, 3, &masking_challenge_gpu);
                set_bytes(encoder, 4, &beq_params);
            },
        );
        let beq_us = beq_start.map_or(0, |start| start.elapsed().as_micros());

        let eval_partials_start = timing.then(Instant::now);
        let partial_count = half_size.div_ceil(REDUCE_CHUNK);
        let row_count = gammas.len() * vector_count;
        let partials = runtime.pooled_buffer::<GpuField>(row_count * partial_count);
        let evals = runtime.pooled_buffer::<GpuField>(row_count);
        let eval_params = GammaEvalParams {
            half_size:              half_size as u32,
            weight_size:            weight_size as u32,
            vector_count:           vector_count as u32,
            vectors_per_polynomial: vectors_per_polynomial as u32,
            gamma_count:            gammas.len() as u32,
            partial_count:          partial_count as u32,
            values_per_partial:     REDUCE_CHUNK as u32,
            _pad0:                  0,
        };
        self.launch_1d(
            &BufferlessPipeline(|runtime| &runtime.gamma_eval_partials_pipeline),
            row_count * partial_count,
            |encoder| {
                set_buffer(encoder, 0, eq_half, 0);
                set_buffer(encoder, 1, packed_vectors.buffer.as_ref(), 0);
                set_buffer(encoder, 2, partials.as_ref(), 0);
                set_bytes(encoder, 3, &masking_challenge_gpu);
                set_bytes(encoder, 4, &eval_params);
            },
        );
        let eval_partials_us = eval_partials_start.map_or(0, |start| start.elapsed().as_micros());
        let eval_reduce_start = timing.then(Instant::now);
        let reduce_params = GammaReduceParams {
            row_count:     row_count as u32,
            partial_count: partial_count as u32,
            _pad0:         0,
            _pad1:         0,
        };
        self.launch_1d(
            &BufferlessPipeline(|runtime| &runtime.gamma_eval_reduce_pipeline),
            row_count,
            |encoder| {
                set_buffer(encoder, 0, partials.as_ref(), 0);
                set_buffer(encoder, 1, evals.as_ref(), 0);
                set_bytes(encoder, 2, &reduce_params);
            },
        );
        let eval_reduce_us = eval_reduce_start.map_or(0, |start| start.elapsed().as_micros());

        let read_start = timing.then(Instant::now);
        let evals = runtime
            .buffer_slice::<GpuField>(evals.as_ref(), row_count)
            .iter()
            .copied()
            .map(gpu_to_fr)
            .collect::<Vec<_>>();
        let stride_per_poly = num_witness_variables + 2;
        let stride_per_gamma = num_polynomials * stride_per_poly;
        let mut eval_results = vec![Fr::ZERO; gammas.len() * stride_per_gamma];
        for (gamma_index, &gamma) in gammas.iter().enumerate() {
            for poly_index in 0..num_polynomials {
                let eval_base = gamma_index * vector_count + poly_index * vectors_per_polynomial;
                let output_base = gamma_index * stride_per_gamma + poly_index * stride_per_poly;
                let m_eval = evals[eval_base];
                eval_results[output_base] = m_eval;
                let mut h = m_eval;
                let mut beta_power = blinding_challenge;
                let mut gamma_power = gamma;
                for witness_index in 0..num_witness_variables {
                    let g_hat_eval = evals[eval_base + 1 + witness_index];
                    eval_results[output_base + 1 + witness_index] = g_hat_eval;
                    h += beta_power * gamma_power * g_hat_eval;
                    beta_power *= blinding_challenge;
                    gamma_power = gamma_power.square();
                }
                eval_results[output_base + 1 + num_witness_variables] = h;
            }
        }
        let read_us = read_start.map_or(0, |start| start.elapsed().as_micros());

        if let Some(total_start) = total_start {
            eprintln!(
                "METAL_WHIR_GAMMA_BLOCK gammas={} half_size={} vector_count={} partial_count={} \
                 eq_us={} beq_us={} eval_partials_us={} eval_reduce_us={} read_us={} total_us={}",
                gammas.len(),
                half_size,
                vector_count,
                partial_count,
                eq_us,
                beq_us,
                eval_partials_us,
                eval_reduce_us,
                read_us,
                total_start.elapsed().as_micros(),
            );
        }

        Some((
            eval_results,
            Box::new(MetalDeviceVector::new(weight_size, beq)),
        ))
    }

    fn commit_device_vector(
        &self,
        vector: &dyn DeviceVector<Fr>,
        masks: &[Fr],
        codeword_length: usize,
        interleaving_depth: usize,
        matrix_commit: &MatrixCommitConfig<Fr>,
    ) -> Option<IrsCommitArtifact<Fr>> {
        let vector = self.metal_vector(vector);
        let matrix = self
            .encode_device_vector_matrix(
                vector.buffer.as_ref(),
                vector.len,
                masks,
                codeword_length,
                interleaving_depth,
            )
            .ok()?;
        let leaf_hashes = self.hash_rows_to_buffer(&matrix).ok()?;
        let merkle_witness = self
            .build_merkle_witness(matrix_commit, &leaf_hashes)
            .ok()?;
        Some(IrsCommitArtifact {
            root:           merkle_witness.root(),
            rows:           std::sync::Arc::new(super::types::DeviceRows {
                rows:   matrix.rows,
                cols:   matrix.cols,
                buffer: matrix.buffer,
            }),
            matrix_witness: merkle_witness,
        })
    }
}
