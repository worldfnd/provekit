import { BackendType, Barretenberg, UltraHonkBackend } from "./vendor/bb/index.js";
import { Noir } from "@noir-lang/noir_js";

type WorkloadName =
  | "passport_complete_age_check"
  | "passport_p1"
  | "webauthn_assertion"
  | "oprf_taceo"
  | "oprf_world_id_nullifier";
type PhaseName = "witness" | "prove" | "verify" | "e2e";

interface BenchSpec {
  name: string;
  iterations: number;
  warmup: number;
  timing_mode?: "cold_local" | "warm_reuse";
  /** Requested bb.js worker count. 1 keeps the historical single-thread path. */
  threads?: number;
}

interface ProofData {
  proof: Uint8Array;
  publicInputs: string[];
}

interface CircuitArtifact {
  bytecode: string;
  [key: string]: unknown;
}

interface WindowWithMobench extends Window {
  mobench: {
    run(spec: BenchSpec): Promise<unknown>;
  };
}

const workloadNames = new Set<WorkloadName>([
  "passport_complete_age_check",
  "passport_p1",
  "webauthn_assertion",
  "oprf_taceo",
  "oprf_world_id_nullifier",
]);
const phaseNames = new Set<PhaseName>(["witness", "prove", "verify", "e2e"]);
const status = document.querySelector<HTMLElement>("#status");

function setProgress(stage: string, started: number): void {
  const elapsedMs = Math.round(performance.now() - started);
  Object.assign(window, {
    __BARRETENBERG_PROGRESS__: {
      stage,
      elapsed_ms: elapsedMs,
    },
  });
  if (status) status.textContent = `${stage} (${elapsedMs} ms)`;
}

function boundedInteger(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function resolveThreads(requested: number | undefined): { requested: number; effective: number } {
  const value = requested ?? 1;
  const bounded = boundedInteger(value, 1, 32, "threads");
  const hardware = navigator.hardwareConcurrency || 1;
  return { requested: bounded, effective: Math.min(bounded, hardware, 32) };
}

function parseFunction(name: string): { workload: WorkloadName; phase: PhaseName } {
  const match = /^barretenberg::([^:]+)::(witness|prove|verify|e2e)$/.exec(name);
  if (!match) throw new Error(`unsupported Barretenberg benchmark function: ${name}`);
  const workload = match[1] as WorkloadName;
  const phase = match[2] as PhaseName;
  if (!workloadNames.has(workload) || !phaseNames.has(phase)) {
    throw new Error(`unsupported Barretenberg benchmark function: ${name}`);
  }
  return { workload, phase };
}

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`failed to fetch ${path}: HTTP ${response.status}`);
  return (await response.json()) as T;
}

async function fetchBytes(path: string): Promise<Uint8Array> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`failed to fetch ${path}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function contentLength(path: string): Promise<number> {
  const response = await fetch(path, { method: "HEAD", cache: "no-store" });
  if (!response.ok) throw new Error(`failed to inspect ${path}: HTTP ${response.status}`);
  const bytes = Number.parseInt(response.headers.get("content-length") ?? "", 10);
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error(`missing Content-Length for ${path}`);
  return bytes;
}

function durationNs(start: number): number {
  return Math.round((performance.now() - start) * 1_000_000);
}

async function run(spec: BenchSpec): Promise<unknown> {
  const coldStarted = performance.now();
  const iterations = boundedInteger(spec.iterations, 1, 20, "iterations");
  const warmup = boundedInteger(spec.warmup, 0, 10, "warmup");
  const threads = resolveThreads(spec.threads);
  const { workload, phase } = parseFunction(spec.name);
  const benchmarkStarted = performance.now();
  setProgress(`Loading ${spec.name}`, benchmarkStarted);

  const [circuit, inputs, frozenWitness, frozenProofBytes, frozenPublicInputs, circuitBytes, inputBytes] = await Promise.all([
    fetchJson<CircuitArtifact>(`./assets/${workload}/circuit.json`),
    fetchJson<Record<string, unknown>>(`./assets/${workload}/inputs.json`),
    fetchBytes(`./assets/${workload}/witness.gz`),
    fetchBytes(`./assets/${workload}/proof.bin`),
    fetchJson<string[]>(`./assets/${workload}/public-inputs.json`),
    contentLength(`./assets/${workload}/circuit.json`),
    contentLength(`./assets/${workload}/inputs.json`),
  ]);
  const noir = new Noir(circuit);
  const backendType = threads.effective > 1 ? BackendType.WasmWorker : BackendType.Wasm;
  const api = await Barretenberg.new({ backend: backendType, threads: threads.effective });
  const backend = new UltraHonkBackend(circuit.bytecode, api);

  try {
    let preparedWitness = frozenWitness;
    let preparedProof: ProofData = {
      proof: frozenProofBytes,
      publicInputs: frozenPublicInputs,
    };
    if ((phase === "witness" || phase === "e2e") && spec.timing_mode !== "cold_local") {
      setProgress("Canary witness", benchmarkStarted);
      preparedWitness = (await noir.execute(inputs)).witness;
      setProgress("Canary proof", benchmarkStarted);
      preparedProof = (await backend.generateProof(preparedWitness)) as ProofData;
    } else if (phase === "prove") {
      setProgress("Canary proof from frozen witness", benchmarkStarted);
      preparedProof = (await backend.generateProof(preparedWitness)) as ProofData;
    }
    let tamperedRejected = false;
    if (spec.timing_mode !== "cold_local") {
      setProgress("Canary verification", benchmarkStarted);
      if (!(await backend.verifyProof(preparedProof))) {
        throw new Error(`Barretenberg rejected its ${workload} canary proof`);
      }
      setProgress("Tampered-proof verification", benchmarkStarted);
      const tamperedBytes = preparedProof.proof.slice();
      tamperedBytes[Math.floor(tamperedBytes.byteLength / 2)] ^= 1;
      try {
        tamperedRejected = !(await backend.verifyProof({
          ...preparedProof,
          proof: tamperedBytes,
        }));
      } catch {
        tamperedRejected = true;
      }
      if (!tamperedRejected) {
        throw new Error(`Barretenberg accepted a tampered ${workload} proof`);
      }
    }

    const samples: Array<{
      duration_ns: number;
      initialization_time_ns: number;
      witness_time_ns: number;
      prove_time_ns: number;
      verify_time_ns: number;
      input_to_proof_time_ns: number;
      proof_size_bytes: number;
      tampered_proof_rejected: boolean;
      sample_index: number;
      warmup: boolean;
    }> = [];
    const timeline: Array<{
      phase: string;
      timing_scope: string;
      start_offset_ns: number;
      end_offset_ns: number;
      iteration: number | null;
    }> = [];
    const runStart = performance.now();

    for (let index = 0; index < warmup + iterations; index += 1) {
      const measured = index >= warmup;
      const iteration = measured ? index - warmup : null;
      const started = spec.timing_mode === "cold_local" && index === 0
        ? coldStarted
        : performance.now();
      setProgress(
        `${measured ? "Sample" : "Warmup"} ${index + 1}/${warmup + iterations}: ${phase}`,
        benchmarkStarted,
      );

      let initializationNs = 0;
      let witnessNs = 0;
      let proveNs = 0;
      let verifyNs = 0;
      let inputToProofNs = 0;
      let sampleProof = preparedProof;
      if (phase === "witness") {
        const witnessStarted = performance.now();
        await noir.execute(inputs);
        witnessNs = durationNs(witnessStarted);
      } else if (phase === "prove") {
        const proveStarted = performance.now();
        sampleProof = (await backend.generateProof(preparedWitness)) as ProofData;
        proveNs = durationNs(proveStarted);
      } else if (phase === "verify") {
        const verifyStarted = performance.now();
        if (!(await backend.verifyProof(preparedProof))) {
          throw new Error(`Barretenberg rejected ${workload} during verification sample`);
        }
        verifyNs = durationNs(verifyStarted);
      } else {
        const witnessStarted = performance.now();
        const execution = await noir.execute(inputs);
        witnessNs = durationNs(witnessStarted);
        const proveStarted = performance.now();
        sampleProof = (await backend.generateProof(execution.witness)) as ProofData;
        proveNs = durationNs(proveStarted);
        inputToProofNs = durationNs(started);
      }

      if (spec.timing_mode === "cold_local") {
        const verifyStarted = performance.now();
        if (!(await backend.verifyProof(sampleProof))) {
          throw new Error(`Barretenberg rejected ${workload} during cold-run verification`);
        }
        verifyNs = durationNs(verifyStarted);
        const tamperedBytes = sampleProof.proof.slice();
        tamperedBytes[Math.floor(tamperedBytes.byteLength / 2)] ^= 1;
        try {
          tamperedRejected = !(await backend.verifyProof({ ...sampleProof, proof: tamperedBytes }));
        } catch {
          tamperedRejected = true;
        }
        if (!tamperedRejected) {
          throw new Error(`Barretenberg accepted a tampered ${workload} cold-run proof`);
        }
      }

      const elapsed = durationNs(started);
      initializationNs = spec.timing_mode === "cold_local"
        ? inputToProofNs - witnessNs - proveNs
        : 0;
      samples.push({
        duration_ns: elapsed,
        initialization_time_ns: initializationNs,
        witness_time_ns: witnessNs,
        prove_time_ns: proveNs,
        verify_time_ns: verifyNs,
        input_to_proof_time_ns: inputToProofNs || elapsed,
        proof_size_bytes: sampleProof.proof.byteLength,
        tampered_proof_rejected: tamperedRejected,
        sample_index: measured ? index - warmup : index,
        warmup: !measured,
      });
      timeline.push({
        phase,
        timing_scope: phase === "e2e"
          ? "raw-input-to-serialized-proof; verification excluded"
          : phase,
        start_offset_ns: Math.round((started - runStart) * 1_000_000),
        end_offset_ns: Math.round((performance.now() - runStart) * 1_000_000),
        iteration,
      });
    }

    const report = {
      spec: {
        name: spec.name,
        iterations,
        warmup,
      },
      samples,
      phases: [],
      timeline,
      metadata: {
        backend: threads.effective > 1
          ? "barretenberg_4.2.0-aztecnr-rc.2_wasm_workers"
          : "barretenberg_4.2.0-aztecnr-rc.2_wasm_single",
        workload,
        phase,
        timing_mode: spec.timing_mode ?? "warm_reuse",
        circuit_size_bytes: circuitBytes,
        input_size_bytes: inputBytes,
        proof_size_bytes: preparedProof.proof.byteLength,
        public_input_count: preparedProof.publicInputs.length,
        tampered_proof_rejected: tamperedRejected,
        user_agent: navigator.userAgent,
        hardware_concurrency: navigator.hardwareConcurrency,
        threads_requested: threads.requested,
        threads_effective: threads.effective,
        shared_array_buffer: typeof SharedArrayBuffer !== "undefined",
        cross_origin_isolated: self.crossOriginIsolated,
      },
    };
    if (status) status.textContent = JSON.stringify(report, null, 2);
    return report;
  } finally {
    await api.destroy();
    const destroy = (noir as Noir & { destroy?: () => Promise<void> | void }).destroy;
    if (destroy) await destroy.call(noir);
  }
}

(window as unknown as WindowWithMobench).mobench = { run };
