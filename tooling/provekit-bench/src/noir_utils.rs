//! Utilities for working with Noir programs in benchmarks and tests

use {
    anyhow::{Context, Result},
    provekit_common::{file::read, NoirProof, NoirProofScheme},
    std::path::Path,
};

/// Load a proof scheme from a file with error context
pub fn load_proof_scheme<P: AsRef<Path>>(path: P) -> Result<NoirProofScheme> {
    let path = path.as_ref();
    read::<NoirProofScheme>(path)
        .with_context(|| format!("Failed to load proof scheme from {}", path.display()))
}

/// Load a proof from a file with error context
pub fn load_proof<P: AsRef<Path>>(path: P) -> Result<NoirProof> {
    let path = path.as_ref();
    read::<NoirProof>(path).with_context(|| format!("Failed to load proof from {}", path.display()))
}

/// Check if a file exists and provide helpful error message if not
pub fn ensure_file_exists<P: AsRef<Path>>(path: P, file_type: &str) -> Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(anyhow::anyhow!(
            "{} file not found at {}. Make sure to run the appropriate setup commands first.",
            file_type,
            path.display()
        ));
    }
    Ok(())
}

/// Helper to create relative paths for benchmark data
pub fn benchmark_data_path(filename: &str) -> std::path::PathBuf {
    std::path::Path::new("benches").join(filename)
}

/// Helper to create relative paths to noir examples
pub fn noir_example_path(example_name: &str) -> std::path::PathBuf {
    std::path::Path::new("../../noir-examples").join(example_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_helpers() {
        let bench_path = benchmark_data_path("test.nps");
        assert_eq!(bench_path, std::path::Path::new("benches/test.nps"));

        let example_path = noir_example_path("poseidon-rounds");
        assert_eq!(
            example_path,
            std::path::Path::new("../../noir-examples/poseidon-rounds")
        );
    }
}
