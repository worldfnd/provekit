use {
    crate::witness::WitnessBuilder,
    serde::{Deserialize, Serialize},
};

mod dependency;
mod remapper;
mod scheduler;
mod splitter;

pub use {
    dependency::DependencyInfo, remapper::WitnessIndexRemapper, scheduler::LayerScheduler,
    splitter::WitnessSplitter,
};

/// Type of operations contained in a layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LayerType {
    /// Regular operations (non-inverse).
    Other,
    /// Field inversion operations that should be batch computed.
    Inverse,
}

/// A single layer in the execution plan.
///
/// Each layer groups witness builders that should be executed together,
/// either as regular operations or as a batch of field inversions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Layer {
    /// The witness builders to execute in this layer.
    pub witness_builders: Vec<WitnessBuilder>,
    /// The type of operations in this layer.
    pub typ:              LayerType,
}

/// Execution plan for witness computation with batched field inversions.
///
/// Organizes witness builders into layers where layers alternate between:
/// 1. Regular operations (LayerType::Other)
/// 2. Batched inverse operations (LayerType::Inverse)
///
/// This enables Montgomery's batch inversion trick: instead of computing n
/// individual field inversions (expensive), we compute them in a batch using
/// only 1 inversion and 3n multiplications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LayeredWitnessBuilders {
    /// The layers of witness builders in execution order.
    pub layers: Vec<Layer>,
}

impl LayeredWitnessBuilders {
    /// Returns the total number of layers.
    pub fn layers_len(&self) -> usize {
        self.layers.len()
    }
}

/// Split witness builders for sound challenge generation.
///
/// Contains w1 (pre-challenge commitment) and w2 (post-challenge) witness
/// builders, each with their own layered execution plans.
/// Reference: https://hackmd.io/@shreyas-londhe/HkgVaTXCxx
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitWitnessBuilders {
    /// Witness builders that must be computed before challenge extraction.
    /// These are committed to w1 before challenges are generated.
    pub w1_layers: LayeredWitnessBuilders,
    /// Witness builders computed after challenge extraction.
    /// These include challenges themselves and anything depending on them.
    pub w2_layers: LayeredWitnessBuilders,
    /// Number of witnesses in w1 (used for indexing split).
    pub w1_size:   usize,
}
