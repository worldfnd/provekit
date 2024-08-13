mod types;
mod utils;
use acir::circuit::{opcodes::BlackBoxFuncCall, Opcode};
use clap::{Parser, ValueEnum};
use types::Program;
use utils::program_at_path;
/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
  /// Name of the person to greet
  cmd: Command,

  /// Path to circuit file
  path: String,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Command {
  /// Compile the ACIR to R1CS
  R1CS,
}

fn main() {
  let args = Args::parse();

  match args.cmd {
    Command::R1CS => {
      let program = program_at_path(args.path);

      assert!(
        program.functions.len() == 1,
        "only one function supported at the moment",
      );
      let Program {
        mut functions,
        unconstrained_functions: _,
      } = program;
      let circuit = functions.pop().unwrap();

      let iter = circuit.opcodes.iter();

      let mut assert_0_count = 0;

      for opcode in iter {
        match opcode {
          Opcode::AssertZero(_expr) => assert_0_count += 1,
          Opcode::BlackBoxFuncCall(bb_fn_call) => match bb_fn_call {
            BlackBoxFuncCall::AND { lhs, rhs, output } => {
              println!("BB AND")
            }
            BlackBoxFuncCall::XOR { lhs, rhs, output } => {
              println!("BB XOR")
            }
            BlackBoxFuncCall::RANGE { input } => {
              println!("BB RANGE")
            }
            _ => {
              // Unsupported operations: AES128Encrypt, SHA256, Blake2s, Blake3, SchnorrVerify, PedersenCommitment,
              // PedersenHash, EcdsaSecp256k1, EcdsaSecp256r1, MultiScalarMul, EmbeddedCurveAdd, Keccak256, Keccakf1600,
              // RecursiveAggregation, BigIntAdd, BigIntSub, BigIntMul, BigIntDiv, BigIntFromLeBytes, BigIntToLeBytes,
              // Poseidon2Permutation, Sha256Compression
              println!("Unsupprted BlackBoxFuncCall")
            }
          },
          Opcode::Directive(_) => println!("Directive",),
          Opcode::MemoryOp {
            block_id,
            op,
            predicate,
          } => println!("MemoryOp",),
          Opcode::MemoryInit {
            block_id,
            init,
            block_type,
          } => println!("MemoryInit",),
          Opcode::BrilligCall {
            id,
            inputs,
            outputs,
            predicate,
          } => println!("BrilligCall",),
          Opcode::Call {
            id,
            inputs,
            outputs,
            predicate,
          } => println!("Call",),
        }
      }

      println!("Opcodes : {:?}", circuit.opcodes.len());
    }
  }
}
