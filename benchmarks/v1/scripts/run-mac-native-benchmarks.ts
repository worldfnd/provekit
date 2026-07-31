import { mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";

type Sample = {
  iteration: number;
  duration_ms: number;
  max_rss_bytes: number | null;
  proof_size_bytes: number;
};

const scriptDirectory = dirname(new URL(import.meta.url).pathname);
const benchmarkRoot = resolve(scriptDirectory, "..");
const repoRoot = resolve(benchmarkRoot, "../..");
const campaign =
  process.env.MAC_BENCHMARK_CAMPAIGN ??
  new Date().toISOString().replaceAll(":", "").replaceAll(".", "-");
const outputRoot = resolve(
  process.env.MAC_BENCHMARK_OUTPUT ??
    `${repoRoot}/target/v1-benchmarks/results/mac-benchmarks/${campaign}/native`,
);
const publicationOutput = resolve(
  process.env.MAC_BENCHMARK_JSON ??
    `${benchmarkRoot}/results/run-30041758043/mac-native-benchmarks.json`,
);
const timeBinary = "/usr/bin/time";
const warmup = 1;
const iterations = 5;

async function command(
  args: string[],
  options: { cwd?: string; stdout?: "inherit" | "pipe"; stderr?: "inherit" | "pipe" } = {},
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const process = Bun.spawn(args, {
    cwd: options.cwd ?? repoRoot,
    stdout: options.stdout ?? "pipe",
    stderr: options.stderr ?? "pipe",
    env: processEnv(),
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
    process.exited,
  ]);
  return { stdout, stderr, exitCode };
}

function processEnv(): Record<string, string> {
  return Object.fromEntries(
    Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

async function checked(args: string[], cwd = repoRoot): Promise<string> {
  const result = await command(args, { cwd });
  if (result.exitCode !== 0) {
    throw new Error(
      `${args.join(" ")} failed (${result.exitCode})\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result.stdout.trim();
}

async function measured(
  args: string[],
  timePath: string,
  cwd = repoRoot,
): Promise<{
  durationMs: number;
  maxRssBytes: number | null;
  stdout: string;
  stderr: string;
}> {
  const result = await command([timeBinary, "-l", "-o", timePath, ...args], { cwd });
  if (result.exitCode !== 0) {
    throw new Error(
      `${args.join(" ")} failed (${result.exitCode})\n${result.stdout}\n${result.stderr}`,
    );
  }
  const timing = await Bun.file(timePath).text();
  const real = /^\s*([0-9.]+)\s+real/m.exec(timing);
  const rss = /^\s*([0-9]+)\s+maximum resident set size/m.exec(timing);
  if (!real) throw new Error(`could not parse elapsed time from ${timePath}`);
  return {
    durationMs: Number.parseFloat(real[1]) * 1_000,
    maxRssBytes: rss ? Number.parseInt(rss[1], 10) : null,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

async function size(path: string): Promise<number> {
  return Bun.file(path).size;
}

function median(values: number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}

function summary(samples: Sample[]) {
  const durations = samples.map(({ duration_ms }) => duration_ms);
  const rss = samples
    .map(({ max_rss_bytes }) => max_rss_bytes)
    .filter((value): value is number => value !== null);
  const proofSizes = samples.map(({ proof_size_bytes }) => proof_size_bytes);
  return {
    median_ms: median(durations),
    min_ms: Math.min(...durations),
    max_ms: Math.max(...durations),
    max_process_peak_bytes: rss.length === 0 ? null : Math.max(...rss),
    proof_size_bytes: median(proofSizes),
    proof_sizes_bytes: proofSizes,
  };
}

async function tamperBinary(source: string, destination: string): Promise<void> {
  const bytes = new Uint8Array(await Bun.file(source).arrayBuffer());
  bytes[Math.floor(bytes.byteLength / 2)] ^= 1;
  await Bun.write(destination, bytes);
}

async function runProveKit() {
  const cli = resolve(repoRoot, "target/release/provekit-cli");
  if (!(await Bun.file(cli).exists())) {
    await checked(["cargo", "build", "--release", "-p", "provekit-cli"]);
  }
  const definitions = [
    {
      workload: "passport_complete_age_check",
      input: resolve(
        repoRoot,
        "noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml",
      ),
    },
    {
      workload: "webauthn_assertion",
      input: resolve(benchmarkRoot, "noir/webauthn_assertion/Prover.toml"),
    },
    {
      workload: "oprf_taceo",
      input: resolve(repoRoot, "target/v1-benchmarks/sources/oprf-nr/oprf_example/Prover.toml"),
    },
  ];
  const results = [];
  for (const definition of definitions) {
    console.error(`[native] ProveKit ${definition.workload}`);
    const artifactRoot = resolve(
      repoRoot,
      `target/v1-benchmarks/artifacts/${definition.workload}`,
    );
    const pkp = resolve(artifactRoot, `${definition.workload}.pkp`);
    const pkv = resolve(artifactRoot, `${definition.workload}.pkv`);
    const work = resolve(outputRoot, `provekit/${definition.workload}`);
    await mkdir(work, { recursive: true });
    const samples: Sample[] = [];
    let lastProof = "";
    for (let run = 0; run < warmup + iterations; run += 1) {
      const proof = resolve(work, `proof-${run}.np`);
      const timing = resolve(work, `prove-${run}.time`);
      const measuredRun = await measured([
        cli,
        "prove",
        "--prover",
        pkp,
        "--input",
        definition.input,
        "--out",
        proof,
      ], timing);
      await checked([cli, "verify", "--verifier", pkv, "--proof", proof]);
      lastProof = proof;
      if (run >= warmup) {
        samples.push({
          iteration: run - warmup,
          duration_ms: measuredRun.durationMs,
          max_rss_bytes: measuredRun.maxRssBytes,
          proof_size_bytes: await size(proof),
        });
      }
    }
    const tampered = resolve(work, "proof-tampered.np");
    await tamperBinary(lastProof, tampered);
    const tamperResult = await command([cli, "verify", "--verifier", pkv, "--proof", tampered]);
    if (tamperResult.exitCode === 0) {
      throw new Error(`ProveKit accepted a tampered ${definition.workload} proof`);
    }
    results.push({
      workload: definition.workload,
      backend: "provekit_v1_native",
      sampling: { warmup, iterations },
      samples,
      summary: summary(samples),
      artifacts: {
        prover_bundle_bytes: await size(pkp),
        verifier_bytes: await size(pkv),
      },
      verification: { valid_proofs_verified: true, tampered_proof_rejected: true },
    });
  }
  return results;
}

async function runBarretenberg() {
  const bootstrap = resolve(scriptDirectory, "bootstrap-barretenberg.sh");
  const bb = (await checked([bootstrap])).split("\n").at(-1)!;
  const version = await checked([bb, "--version"]);
  const crs = resolve(repoRoot, "target/v1-benchmarks/tools/barretenberg-0.87.0/crs");
  await mkdir(crs, { recursive: true });
  const definitions = [
    "passport_complete_age_check",
    "webauthn_assertion",
    "oprf_taceo",
  ];
  const results = [];
  for (const workload of definitions) {
    console.error(`[native] Barretenberg ${workload}`);
    const assets = resolve(benchmarkRoot, `barretenberg/web/dist/assets/${workload}`);
    const circuit = (await Bun.file(resolve(assets, "circuit.json")).json()) as {
      bytecode: string;
    };
    const work = resolve(outputRoot, `barretenberg/${workload}`);
    await mkdir(work, { recursive: true });
    const bytecode = resolve(work, "bytecode.gz");
    await Bun.write(bytecode, Uint8Array.from(Buffer.from(circuit.bytecode, "base64")));
    const witness = resolve(assets, "witness.gz");
    const vk = resolve(work, "vk");
    const setupRoot = resolve(work, "setup");
    await rm(setupRoot, { recursive: true, force: true });
    await mkdir(setupRoot, { recursive: true });
    await checked([
      bb,
      "prove",
      "-s",
      "ultra_honk",
      "-b",
      bytecode,
      "-w",
      witness,
      "-o",
      setupRoot,
      "-c",
      crs,
      "--output_format",
      "bytes",
      "--write_vk",
    ]);
    await Bun.write(vk, Bun.file(resolve(setupRoot, "vk")));

    const samples: Sample[] = [];
    let lastProof = "";
    let lastPublic = "";
    for (let run = 0; run < warmup + iterations; run += 1) {
      const runRoot = resolve(work, `run-${run}`);
      await mkdir(runRoot, { recursive: true });
      const timing = resolve(runRoot, "prove.time");
      const measuredRun = await measured([
        bb,
        "prove",
        "-s",
        "ultra_honk",
        "-b",
        bytecode,
        "-w",
        witness,
        "-o",
        runRoot,
        "-c",
        crs,
        "--output_format",
        "bytes",
      ], timing);
      const proof = resolve(runRoot, "proof");
      const publicInputs = resolve(runRoot, "public_inputs");
      await checked([
        bb,
        "verify",
        "-s",
        "ultra_honk",
        "-i",
        publicInputs,
        "-p",
        proof,
        "-k",
        vk,
        "-c",
        crs,
      ]);
      lastProof = proof;
      lastPublic = publicInputs;
      if (run >= warmup) {
        samples.push({
          iteration: run - warmup,
          duration_ms: measuredRun.durationMs,
          max_rss_bytes: measuredRun.maxRssBytes,
          proof_size_bytes: await size(proof),
        });
      }
    }
    const tampered = resolve(work, "proof-tampered");
    await tamperBinary(lastProof, tampered);
    const tamperResult = await command([
      bb,
      "verify",
      "-s",
      "ultra_honk",
      "-i",
      lastPublic,
      "-p",
      tampered,
      "-k",
      vk,
      "-c",
      crs,
    ]);
    if (tamperResult.exitCode === 0) {
      throw new Error(`Barretenberg accepted a tampered ${workload} proof`);
    }
    const crsFiles = await Array.fromAsync(
      new Bun.Glob("*").scan({ cwd: crs, absolute: true, onlyFiles: true }),
    );
    const crsBytes = (
      await Promise.all(crsFiles.map(async (path) => ({ path, bytes: await size(path) })))
    ).reduce((total, file) => total + file.bytes, 0);
    results.push({
      workload,
      backend: "barretenberg_native",
      backend_version: version,
      threads: 16,
      sampling: { warmup, iterations },
      samples,
      summary: summary(samples),
      artifacts: {
        circuit_bytecode_bytes: await size(bytecode),
        crs_bytes: crsBytes,
        prover_bundle_bytes: (await size(bytecode)) + crsBytes,
        verification_key_bytes: await size(vk),
      },
      verification: { valid_proofs_verified: true, tampered_proof_rejected: true },
    });
  }
  return results;
}

async function runRapidsnark() {
  await checked([resolve(scriptDirectory, "build-rapidsnark-host.sh")]);
  const source = resolve(repoRoot, "target/v1-benchmarks/sources/rapidsnark");
  const prover = resolve(source, "package_macos_arm64/bin/prover");
  const verifier = resolve(source, "package_macos_arm64/bin/verifier");
  const definitions = [
    "register_sha256_sha256_sha256_rsa_65537_4096",
    "vc_and_disclose",
  ];
  const results = [];
  for (const workload of definitions) {
    console.error(`[native] Rapidsnark ${workload}`);
    const sourceRoot = resolve(repoRoot, `target/v1-benchmarks/groth16/self/${workload}`);
    const zkey = resolve(sourceRoot, `${workload}_0000.zkey`);
    const witness = resolve(
      repoRoot,
      `target/v1-benchmarks/circom-witnesses/self/${workload}/wasm.wtns`,
    );
    const verificationKey = resolve(sourceRoot, "verification_key.json");
    const work = resolve(outputRoot, `rapidsnark/${workload}`);
    await mkdir(work, { recursive: true });
    const samples: Sample[] = [];
    let lastProof = "";
    let lastPublic = "";
    for (let run = 0; run < warmup + iterations; run += 1) {
      const proof = resolve(work, `proof-${run}.json`);
      const publicInputs = resolve(work, `public-${run}.json`);
      const timing = resolve(work, `prove-${run}.time`);
      const measuredRun = await measured([prover, zkey, witness, proof, publicInputs], timing);
      await checked([verifier, verificationKey, publicInputs, proof]);
      lastProof = proof;
      lastPublic = publicInputs;
      if (run >= warmup) {
        samples.push({
          iteration: run - warmup,
          duration_ms: measuredRun.durationMs,
          max_rss_bytes: measuredRun.maxRssBytes,
          proof_size_bytes: await size(proof),
        });
      }
    }
    const proofJson = (await Bun.file(lastProof).json()) as {
      pi_a: string[];
    };
    proofJson.pi_a[0] = proofJson.pi_a[0] === "1" ? "2" : "1";
    const tampered = resolve(work, "proof-tampered.json");
    await Bun.write(tampered, `${JSON.stringify(proofJson)}\n`);
    const tamperResult = await command([verifier, verificationKey, lastPublic, tampered]);
    if (tamperResult.exitCode === 0) {
      throw new Error(`Rapidsnark accepted a tampered ${workload} proof`);
    }
    results.push({
      workload:
        workload === "register_sha256_sha256_sha256_rsa_65537_4096"
          ? "self_passport_registration"
          : "self_passport_disclosure",
      source_workload: workload,
      backend: "rapidsnark_groth16_native",
      sampling: { warmup, iterations },
      samples,
      summary: summary(samples),
      artifacts: {
        proving_key_bytes: await size(zkey),
        verification_key_bytes: await size(verificationKey),
        prover_bundle_lower_bound_bytes: await size(zkey),
      },
      verification: { valid_proofs_verified: true, tampered_proof_rejected: true },
    });
  }
  return results;
}

async function runArkworks() {
  console.error("[native] Arkworks World ID OPRF query and nullifier");
  const crate = resolve(benchmarkRoot, "arkworks-host");
  const target = resolve(repoRoot, "target/v1-benchmarks/arkworks-host");
  await checked(["cargo", "build", "--release", "--target-dir", target], crate);
  const binary = resolve(target, "release/provekit-v1-arkworks-host-bench");
  const artifactLock = (await Bun.file(resolve(benchmarkRoot, "circom/artifacts.lock.json")).json()) as {
    artifacts: Array<{ workload: string; size: number }>;
  };
  const definitions = [
    {
      workload: "world_id_oprf_query",
      function: "zk_mobile_bench::bench_query_proving_only",
    },
    {
      workload: "world_id_oprf_nullifier",
      function: "zk_mobile_bench::bench_nullifier_proving_only",
    },
  ];
  const results = [];
  for (const definition of definitions) {
    const work = resolve(outputRoot, `arkworks/${definition.workload}`);
    await mkdir(work, { recursive: true });
    const timing = resolve(work, "process.time");
    const processMeasurement = await measured(
      [binary, definition.function],
      timing,
      crate,
    );
    const report = JSON.parse(processMeasurement.stdout) as {
      samples: Array<{ duration_ns: number; process_peak_memory_kb?: number }>;
      resource_usage?: { process_peak_memory_kb?: number };
    };
    const bundleBytes = artifactLock.artifacts
      .filter(({ workload }) => workload === definition.workload)
      .reduce((total, artifact) => total + artifact.size, 0);
    results.push({
      workload: definition.workload,
      backend: "circom_compat_arkworks_native",
      sampling: { warmup, iterations },
      samples: report.samples.map((sample, iteration) => ({
        iteration,
        duration_ms: sample.duration_ns / 1_000_000,
        process_peak_bytes:
          sample.process_peak_memory_kb === undefined
            ? null
            : sample.process_peak_memory_kb * 1_000,
      })),
      summary: {
        median_ms: median(report.samples.map(({ duration_ns }) => duration_ns / 1_000_000)),
        min_ms: Math.min(...report.samples.map(({ duration_ns }) => duration_ns / 1_000_000)),
        max_ms: Math.max(...report.samples.map(({ duration_ns }) => duration_ns / 1_000_000)),
        max_process_peak_bytes:
          report.resource_usage?.process_peak_memory_kb === undefined
            ? processMeasurement.maxRssBytes
            : report.resource_usage.process_peak_memory_kb * 1_000,
        proof_size_bytes: null,
      },
      artifacts: { prover_bundle_bytes: bundleBytes },
      verification: {
        valid_proofs_verified: null,
        tampered_proof_rejected: null,
        limitation: "The pinned Mobench proof-only functions discard proof bytes.",
      },
    });
  }
  return results;
}

await mkdir(outputRoot, { recursive: true });
const output = {
  schema_version: 1,
  campaign,
  generated_at: new Date().toISOString(),
  environment: {
    hardware: (await checked(["sysctl", "-n", "machdep.cpu.brand_string"])) || "Apple Silicon",
    memory_bytes: Number.parseInt(await checked(["sysctl", "-n", "hw.memsize"]), 10),
    os: (await checked(["sw_vers", "-productName"])) + " " + (await checked(["sw_vers", "-productVersion"])),
    os_build: await checked(["sw_vers", "-buildVersion"]),
    architecture: await checked(["uname", "-m"]),
  },
  contract: {
    sequential: true,
    warmup,
    measured_iterations: iterations,
    duration: "fresh-process wall clock for native CLI lanes; Mobench duration for Arkworks",
    memory: "maximum resident set size where available",
  },
  results: {
    provekit: await runProveKit(),
    barretenberg: await runBarretenberg(),
    arkworks: await runArkworks(),
    rapidsnark: await runRapidsnark(),
  },
  unavailable: [
    {
      workload: "passport",
      backend: "circom_compat_arkworks_native",
      reason: "Self passport circuits use dynamic Circom control flow unsupported by circom-compat.",
    },
    {
      workload: "webauthn",
      backend: "circom_compat_arkworks_native",
      reason:
        "privacy-ethereum/webauth-circom is compiled, but the Arkworks adapter and benchmark zkey are not prepared.",
    },
    {
      workload: "webauthn",
      backend: "rapidsnark_groth16_native",
      reason:
        "privacy-ethereum/webauth-circom is compiled, but the Rapidsnark adapter and benchmark zkey are not prepared.",
    },
    {
      workload: "oprf",
      backend: "rapidsnark_groth16_native",
      reason: "No Rapidsnark-compatible prepared World ID OPRF zkey is retained.",
    },
  ],
};

await mkdir(dirname(publicationOutput), { recursive: true });
await Bun.write(publicationOutput, `${JSON.stringify(output, null, 2)}\n`);
console.log(publicationOutput);
