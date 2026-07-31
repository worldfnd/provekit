use std::process::ExitCode;

use zk_mobile_bench::{BenchSpec, run_benchmark};

fn main() -> ExitCode {
    let name = match std::env::args().nth(1) {
        Some(name) => name,
        None => {
            eprintln!("usage: provekit-v1-arkworks-host-bench <mobench function>");
            return ExitCode::FAILURE;
        }
    };
    let warmup = std::env::var("MOBENCH_WARMUP")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let iterations = std::env::var("MOBENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(5);

    match run_benchmark(BenchSpec {
        name,
        iterations,
        warmup,
    }) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("failed to encode report: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("benchmark failed: {error}");
            ExitCode::FAILURE
        }
    }
}
