use {
    anyhow::{ensure, Context, Result},
    mobench_sdk::{
        codegen::{
            generate_ios_project_with_backend_options, IosDeploymentTarget, IosProjectOptions,
            IosRunner,
        },
        FfiBackend,
    },
    std::{env, path::PathBuf},
};

fn main() -> Result<()> {
    let mut arguments = env::args_os().skip(1);
    let output = PathBuf::from(arguments.next().context("missing output directory")?);
    let library_name = arguments
        .next()
        .context("missing library name")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("library name is not UTF-8"))?;
    let default_function = arguments
        .next()
        .context("missing default benchmark function")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("default benchmark function is not UTF-8"))?;
    ensure!(
        arguments.next().is_none(),
        "usage: provekit-v1-mobench-ios-scaffold OUTPUT LIBRARY_NAME DEFAULT_FUNCTION"
    );

    generate_ios_project_with_backend_options(
        &output,
        &library_name,
        "BenchRunner",
        "dev.world.provekitv1rapidsnarkoprf",
        &default_function,
        FfiBackend::NativeCAbi,
        IosProjectOptions {
            deployment_target:          IosDeploymentTarget::parse("15.0")?,
            runner:                     IosRunner::Swiftui,
            ios_benchmark_timeout_secs: 7_200,
        },
    )
    .context("generate pinned Mobench iOS native-C-ABI scaffold")
}
