use {
    mobench_sdk::{run_benchmark, BenchSpec},
    provekit_v1_rapidsnark_mobile_webauthn as _,
    std::process::ExitCode,
};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(name) = args.next() else {
        eprintln!("usage: mobench-host <function> [warmup] [iterations]");
        return ExitCode::FAILURE;
    };
    let warmup = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let iterations = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(5);
    let output = args.next();
    match run_benchmark(BenchSpec {
        name,
        iterations,
        warmup,
    }) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                if let Some(path) = output {
                    if let Err(error) = std::fs::write(&path, &json) {
                        eprintln!("failed to write {path}: {error}");
                        return ExitCode::FAILURE;
                    }
                }
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("failed to serialize report: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("benchmark failed: {error}");
            ExitCode::FAILURE
        }
    }
}
