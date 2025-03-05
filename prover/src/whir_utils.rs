use clap::Parser;
use whir::parameters::{
    SoundnessType,
    FoldType,
};
use whir::whir::parameters::WhirConfig;
use whir::crypto::fields::Field256;
use crate::skyscraper::skyscraper_for_whir::SkyscraperMerkleConfig;
use crate::skyscraper::skyscraper_pow::SkyscraperPoW;
use whir::parameters::default_max_pow;
use whir::parameters::MultivariateParameters;
use whir::parameters::WhirParameters;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]

/// Configuration for Gnark
pub struct GnarkConfig {
    /// number of rounds
    pub n_rounds: usize,
    /// number of variables
    pub n_vars: usize,
    /// rate
    pub rate: usize,
    /// folding factor
    pub folding_factor: Vec<usize>,
    /// out of domain samples
    pub ood_samples: Vec<usize>,
    /// number of queries
    pub num_queries: Vec<usize>,
    /// proof of work bits
    pub pow_bits: Vec<i32>,
    /// final queries
    pub final_queries: usize,
    /// final proof of work bits
    pub final_pow_bits: i32,
    /// final folding proof of work bits
    pub final_folding_pow_bits: i32,
    /// domain generator string
    pub domain_generator: String,
    /// nimue input output pattern
    pub io_pattern: String,
    /// transcript in byte form
    pub transcript: Vec<u8>,
    /// length of the transcript
    pub transcript_len: usize
}

/// Command line arguments for WHIR
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Security level
    #[arg(short = 'l', long, default_value = "100")]
    pub security_level: usize,

    /// Proof of work bits
    #[arg(short = 'p', long)]
    pub pow_bits: Option<usize>,

    /// Rate
    #[arg(short = 'r', long, default_value = "1")]
    pub rate: usize,

    /// Folding factor
    #[arg(short = 'k', long = "fold", default_value = "4")]
    pub folding_factor: usize,

    /// Soundness type
    #[arg(long = "sec", default_value = "ConjectureList")]
    pub soundness_type: SoundnessType,

    /// Fold type
    #[arg(long = "fold_type", default_value = "ProverHelps")]
    pub fold_optimisation: FoldType,
}

/// Parse command line parameters turn it into whir params
pub fn parse_args_and_return_whir_params(num_variables: usize) -> WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW> {
    let mut args = Args::parse();

    if args.pow_bits.is_none() {
        args.pow_bits = Some(default_max_pow(num_variables, args.rate));
    }

    let security_level = args.security_level;
    let pow_bits = args.pow_bits.unwrap();
    let starting_rate = args.rate;
    let folding_factor = args.folding_factor;
    let fold_optimisation = args.fold_optimisation;
    let soundness_type = args.soundness_type;

    let mv_params = MultivariateParameters::<Field256>::new(num_variables);

    let whir_params = WhirParameters::<SkyscraperMerkleConfig, SkyscraperPoW> {
        initial_statement: true,
        security_level,
        pow_bits,
        folding_factor: whir::parameters::FoldingFactor::Constant(folding_factor),
        leaf_hash_params: (),
        two_to_one_params: (),
        soundness_type,
        fold_optimisation,
        _pow_parameters: Default::default(),
        starting_log_inv_rate: starting_rate,
    };

    let params = WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>::new(mv_params, whir_params);

    params
}