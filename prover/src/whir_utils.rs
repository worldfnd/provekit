use clap::Parser;
use whir::parameters::{
    SoundnessType,
    FoldType,
};
use whir::whir::parameters::WhirConfig;
use whir::crypto::fields::Field256;
use crate::skyscraper::skyscraper_for_whir::SkyscraperMerkleConfig;
use crate::skyscraper::skyscraper_pow::SkyscraperPoW;
use crate::utils::next_power_of_two;
use whir::parameters::default_max_pow;
use whir::parameters::MultivariateParameters;
use whir::parameters::WhirParameters;

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

    /// Number of variables for the extension polynomial
    #[arg(short = 'd', long, default_value = "20")]
    pub num_variables: usize,

    /// Number of evaluations in Constrained Reed-Solomon code
    #[arg(short = 'e', long = "evaluations", default_value = "1")]
    pub num_evaluations: usize,

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

/// Parse command line parameters and return args and params used for whir
pub fn parse_args(witness_len: usize) -> (Args, WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>) {
    let mut args = Args::parse();
    
    args.num_variables = next_power_of_two(witness_len);
    if args.pow_bits.is_none() {
        args.pow_bits = Some(default_max_pow(args.num_variables, args.rate));
    }

    let security_level = args.security_level;
    let pow_bits = args.pow_bits.unwrap();
    let num_variables = args.num_variables;
    let starting_rate = args.rate;
    let folding_factor = args.folding_factor;
    let fold_optimisation = args.fold_optimisation;
    let soundness_type = args.soundness_type;
    let num_evaluations = args.num_evaluations;

    if num_evaluations == 0 {
        println!("Warning: running as PCS but no evaluations specified.");
    }

    let mv_params = MultivariateParameters::<Field256>::new(num_variables);

    let whir_params = WhirParameters::<SkyscraperMerkleConfig, SkyscraperPoW> {
        initial_statement: true,
        security_level,
        pow_bits,
        folding_factor,
        leaf_hash_params: (),
        two_to_one_params: (),
        soundness_type,
        fold_optimisation,
        _pow_parameters: Default::default(),
        starting_log_inv_rate: starting_rate,
    };

    let params = WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>::new(mv_params, whir_params);

    (args, params)
}