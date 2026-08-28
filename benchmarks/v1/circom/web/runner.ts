import { groth16, wtns } from "snarkjs";

type Workload = "passport" | "webauthn" | "oprf";
type SemanticEquivalence =
  | "closest-analogue-not-equivalent"
  | "p1-matched-monolithic";
interface BenchSpec {
  workload: Workload;
  warmup: number;
  iterations: number;
  single_thread?: boolean;
  /** snarkjs chooses its worker pool from hardwareConcurrency; this is metadata only. */
  prover_threads?: number;
  timing_mode?: "cold_local" | "warm_reuse";
}
interface Fixture {
  circuit: string;
  variant: string;
  wasm: string;
  zkey: string;
  verification_key: string;
  input: string;
  circuit_commit: string;
  semantic_equivalence: SemanticEquivalence;
  profile?: "P1";
  ceremony?: {
    production_safe: boolean;
    final_zkey_sha256: string;
  };
  artifact_hashes?: Record<string, string>;
}
interface ProgressEvent {
  at_ms: number;
  circuit?: string;
  variant?: string;
  sample_index?: number;
  warmup?: boolean;
  stage: string;
  detail?: string;
}
interface Manifest {
  schema_version: 1;
  fixtures: Record<Workload, Fixture[]>;
}

declare global {
  interface Window {
    mobenchCircom: {
      progress: ProgressEvent[];
      run(spec: BenchSpec): Promise<unknown>;
    };
  }
}

const status = document.querySelector<HTMLElement>("#status");
const durationNs = (started: number) => Math.round((performance.now() - started) * 1_000_000);
const progress: ProgressEvent[] = [];

function emit(event: Omit<ProgressEvent, "at_ms">): void {
  const entry = { at_ms: performance.now(), ...event };
  progress.push(entry);
  if (status) status.textContent = `${entry.stage}${entry.detail ? `: ${entry.detail}` : ""}`;
  console.info(`MOBENCH_PROGRESS ${JSON.stringify(entry)}`);
}

async function json<T>(path: string): Promise<T> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`failed to fetch ${path}: HTTP ${response.status}`);
  return (await response.json()) as T;
}

async function contentLength(path: string): Promise<number> {
  const response = await fetch(path, { method: "HEAD", cache: "no-store" });
  if (!response.ok) throw new Error(`failed to inspect ${path}: HTTP ${response.status}`);
  const value = Number.parseInt(response.headers.get("content-length") ?? "", 10);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`missing valid Content-Length for ${path}`);
  }
  return value;
}

function bounded(value: number, min: number, max: number, label: string): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${label} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function tamper(proof: Record<string, unknown>): Record<string, unknown> {
  const copy = structuredClone(proof);
  const piA = copy.pi_a;
  if (!Array.isArray(piA) || typeof piA[0] !== "string") {
    throw new Error("unexpected Groth16 proof representation");
  }
  piA[0] = (BigInt(piA[0]) + 1n).toString();
  return copy;
}

async function runFixture(
  fixture: Fixture,
  warmup: number,
  iterations: number,
  singleThread: boolean,
  timingMode: "cold_local" | "warm_reuse",
  proverThreadsRequested: number,
) {
  const coldStarted = performance.now();
  emit({ circuit: fixture.circuit, variant: fixture.variant, stage: "fixture-load-start" });
  const [input, verificationKey] = await Promise.all([
    json<Record<string, unknown>>(`./assets/${fixture.input}`),
    json<Record<string, unknown>>(`./assets/${fixture.verification_key}`),
  ]);
  const [wasmSizeBytes, zkeySizeBytes, inputSizeBytes] = await Promise.all([
    contentLength(`./assets/${fixture.wasm}`),
    contentLength(`./assets/${fixture.zkey}`),
    contentLength(`./assets/${fixture.input}`),
  ]);
  emit({
    circuit: fixture.circuit,
    variant: fixture.variant,
    stage: "fixture-load-complete",
    detail: `payload=${wasmSizeBytes + zkeySizeBytes + inputSizeBytes}`,
  });
  const samples = [];
  for (let index = 0; index < warmup + iterations; index += 1) {
    const sample = {
      circuit: fixture.circuit,
      variant: fixture.variant,
      sample_index: index < warmup ? index : index - warmup,
      warmup: index < warmup,
    };
    const started = timingMode === "cold_local" && index === 0
      ? coldStarted
      : performance.now();
    const witness = { type: "mem" };
    const witnessStarted = performance.now();
    emit({ ...sample, stage: "witness-start" });
    await wtns.calculate(input, `./assets/${fixture.wasm}`, witness);
    const witnessNs = durationNs(witnessStarted);
    emit({ ...sample, stage: "witness-complete", detail: `${witnessNs}ns` });
    const proveStarted = performance.now();
    emit({ ...sample, stage: "prove-start" });
    const proveProgress = (detail: string) => {
      if (
        /^(Reading|Building|Join ABC|QAP |JoinABC:|Multiexp (start|end):)/.test(detail) ||
        /join\s+\d+\/\d+\s+\d+\/\d+\s+127\/128$/.test(detail)
      ) {
        emit({ ...sample, stage: "prove-progress", detail });
      }
    };
    const logger = {
      debug: proveProgress,
      info: proveProgress,
      warn: (detail: string) => emit({ ...sample, stage: "prove-warning", detail }),
      error: (detail: string) => emit({ ...sample, stage: "prove-error", detail }),
    };
    const result = await groth16.prove(
      `./assets/${fixture.zkey}`,
      witness,
      logger,
      { singleThread },
    );
    const proveNs = durationNs(proveStarted);
    const inputToProofNs = durationNs(started);
    emit({ ...sample, stage: "prove-complete", detail: `${proveNs}ns` });
    const verifyStarted = performance.now();
    emit({ ...sample, stage: "verify-start" });
    if (!(await groth16.verify(verificationKey, result.publicSignals, result.proof))) {
      throw new Error(`SnarkJS rejected ${fixture.circuit}/${fixture.variant}`);
    }
    const verifyNs = durationNs(verifyStarted);
    let tamperedRejected = false;
    try {
      tamperedRejected = !(await groth16.verify(
        verificationKey,
        result.publicSignals,
        tamper(result.proof as Record<string, unknown>),
      ));
    } catch {
      tamperedRejected = true;
    }
    if (!tamperedRejected) throw new Error(`SnarkJS accepted a tampered ${fixture.circuit} proof`);
    emit({ ...sample, stage: "verify-complete", detail: `${verifyNs}ns` });
    samples.push({
      sample_index: index < warmup ? index : index - warmup,
      warmup: index < warmup,
      status: "ok",
      initialization_time_ns: timingMode === "cold_local"
        ? inputToProofNs - witnessNs - proveNs
        : 0,
      witness_time_ns: witnessNs,
      prove_time_ns: proveNs,
      verify_time_ns: verifyNs,
      end_to_end_time_ns: durationNs(started),
      input_to_proof_time_ns: inputToProofNs,
      proof_size_bytes: new TextEncoder().encode(JSON.stringify(result.proof)).byteLength,
      tampered_proof_rejected: tamperedRejected,
    });
  }
  return {
    ...fixture,
    artifacts: {
      wasm_size_bytes: wasmSizeBytes,
      zkey_size_bytes: zkeySizeBytes,
      input_size_bytes: inputSizeBytes,
      proving_payload_size_bytes: wasmSizeBytes + zkeySizeBytes + inputSizeBytes,
    },
    execution: {
      witness_backend: "circom_runtime_wasm_single",
      witness_threads: 1,
      prover_backend: singleThread
        ? "snarkjs_0.7.6_browser_wasm_single_thread"
        : "snarkjs_0.7.6_browser_wasm_workers",
      prover_threads_requested: proverThreadsRequested,
      prover_threads_effective: singleThread
        ? 1
        : Math.min(proverThreadsRequested, navigator.hardwareConcurrency || 1, 64),
      worker_available: typeof Worker !== "undefined",
      hardware_concurrency: navigator.hardwareConcurrency || 1,
      cross_origin_isolated: self.crossOriginIsolated,
    },
    samples,
  };
}

async function run(spec: BenchSpec): Promise<unknown> {
  const warmup = bounded(spec.warmup, 0, 10, "warmup");
  const iterations = bounded(spec.iterations, 1, 20, "iterations");
  const hardwareConcurrency = navigator.hardwareConcurrency || 1;
  const proverThreadsRequested = bounded(
    spec.prover_threads ?? (spec.single_thread === true ? 1 : hardwareConcurrency),
    1,
    64,
    "prover_threads",
  );
  const manifest = await json<Manifest>("./assets/manifest.json");
  const fixtures = manifest.fixtures[spec.workload];
  if (!fixtures?.length) throw new Error(`no Circom browser fixture for ${spec.workload}`);
  const results = [];
  for (const fixture of fixtures) {
    if (status) status.textContent = `Running ${fixture.circuit}/${fixture.variant}`;
    results.push(await runFixture(
      fixture,
      warmup,
      iterations,
      spec.single_thread === true,
      spec.timing_mode ?? "warm_reuse",
      proverThreadsRequested,
    ));
  }
  const report = {
    schema_version: 1,
    stack: "circom_groth16",
    backend: spec.single_thread === true
      ? "snarkjs_0.7.6_browser_wasm_single_thread"
      : "snarkjs_0.7.6_browser_wasm_workers",
    runtime: "browser-wasm",
    workload: spec.workload,
    single_thread: spec.single_thread === true,
    witness_timing: "separate wtns.calculate memory-file phase",
    witness_backend: "circom_runtime_wasm_single",
    witness_threads: 1,
    prover_threads_requested: proverThreadsRequested,
    prover_threads_effective: spec.single_thread === true
      ? 1
      : Math.min(proverThreadsRequested, hardwareConcurrency, 64),
    worker_available: typeof Worker !== "undefined",
    hardware_concurrency: hardwareConcurrency,
    shared_array_buffer: typeof SharedArrayBuffer !== "undefined",
    cross_origin_isolated: self.crossOriginIsolated,
    timing_mode: spec.timing_mode ?? "warm_reuse",
    progress,
    results,
  };
  if (status) status.textContent = "Complete.";
  return report;
}

window.mobenchCircom = { progress, run };
