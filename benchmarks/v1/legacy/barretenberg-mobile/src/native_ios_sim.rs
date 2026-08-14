use {
    anyhow::{bail, Result},
    std::path::Path,
};

/// Placeholder result type for Mobench's unused iOS simulator XCFramework
/// slice. BrowserStack executes the independently linked arm64 device slice.
pub struct ProofBundle {
    pub public_inputs:    Vec<u8>,
    pub proof:            Vec<u8>,
    pub verification_key: Vec<u8>,
}

fn unsupported<T>() -> Result<T> {
    bail!("Barretenberg v0.87 is linked only into the iOS device slice")
}

pub fn initialize_local_crs(_path: &Path) -> Result<()> {
    unsupported()
}

pub fn prove(_circuit: &Path, _witness: &Path, _output: &Path) -> Result<ProofBundle> {
    unsupported()
}

pub fn verify(_public_inputs: &Path, _proof: &Path, _verification_key: &Path) -> Result<bool> {
    unsupported()
}
