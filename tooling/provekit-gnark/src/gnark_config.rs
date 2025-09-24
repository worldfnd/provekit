use {
    provekit_common::{gnark::WHIRConfigGnark, IOPattern, WhirConfig},
    serde::{Deserialize, Serialize},
    std::{fs::File, io::Write},
    tracing::instrument,
};

#[derive(Debug, Serialize, Deserialize)]
/// Configuration for Gnark
pub struct GnarkConfig {
    /// WHIR parameters for witness
    pub whir_config_witness:        WHIRConfigGnark,
    /// WHIR parameters for hiding spartan
    pub whir_config_hiding_spartan: WHIRConfigGnark,
    /// log of number of constraints in R1CS
    pub log_num_constraints:        usize,
    /// log of number of variables in R1CS
    pub log_num_variables:          usize,
    /// log of number of non-zero terms matrix A
    pub log_a_num_terms:            usize,
    /// nimue input output pattern
    pub io_pattern:                 String,
    /// transcript in byte form
    pub transcript:                 Vec<u8>,
    /// length of the transcript
    pub transcript_len:             usize,
}

/// Writes config used for Gnark circuit to a file
#[instrument(skip_all)]
pub fn gnark_parameters(
    whir_params_witness: &WhirConfig,
    whir_params_hiding_spartan: &WhirConfig,
    transcript: &[u8],
    io: &IOPattern,
    m_0: usize,
    m: usize,
    a_num_terms: usize,
) -> GnarkConfig {
    GnarkConfig {
        whir_config_witness:        WHIRConfigGnark::new(whir_params_witness),
        whir_config_hiding_spartan: WHIRConfigGnark::new(whir_params_hiding_spartan),
        log_num_constraints:        m_0,
        log_num_variables:          m,
        log_a_num_terms:            a_num_terms,
        io_pattern:                 String::from_utf8(io.as_bytes().to_vec()).unwrap(),
        transcript:                 transcript.to_vec(),
        transcript_len:             transcript.to_vec().len(),
    }
}

/// Writes config used for Gnark circuit to a file
#[instrument(skip_all)]
pub fn write_gnark_parameters_to_file(
    whir_params_witness: &WhirConfig,
    whir_params_hiding_spartan: &WhirConfig,
    transcript: &[u8],
    io: &IOPattern,
    m_0: usize,
    m: usize,
    a_num_terms: usize,
    file_path: &str,
) {
    let gnark_config = gnark_parameters(
        whir_params_witness,
        whir_params_hiding_spartan,
        transcript,
        io,
        m_0,
        m,
        a_num_terms,
    );
    let mut file_params = File::create(file_path).unwrap();
    file_params
        .write_all(serde_json::to_string(&gnark_config).unwrap().as_bytes())
        .expect("Writing gnark parameters to a file failed");
}
