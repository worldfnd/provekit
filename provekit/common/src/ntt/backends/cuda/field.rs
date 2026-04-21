use {
    super::types::GpuField,
    ark_bn254::{Fr, FrConfig},
    ark_ff::{BigInt, Fp, MontBackend},
    std::marker::PhantomData,
};

pub(super) fn fr_to_gpu(value: Fr) -> GpuField {
    GpuField { limbs: value.0 .0 }
}

pub(super) fn gpu_to_fr(value: GpuField) -> Fr {
    Fp::<MontBackend<FrConfig, 4>, 4>(BigInt(value.limbs), PhantomData)
}
