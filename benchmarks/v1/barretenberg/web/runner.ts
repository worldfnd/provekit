import { BackendType, Barretenberg, UltraHonkBackend } from "./vendor/bb/index.js";
import { Noir } from "@noir-lang/noir_js";

type WorkloadName =
  | "passport_complete_age_check"
  | "webauthn_assertion"
  | "oprf_taceo";
type PhaseName = "witness" | "prove" | "verify" | "e2e";

interface BenchSpec {
  name: string;
  iterations: number;
  warmup: number;
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
  "webauthn_assertion",
  "oprf_taceo",
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

function durationNs(start: number): number {
  return Math.round((performance.now() - start) * 1_000_000);
}

async function run(spec: BenchSpec): Promise<unknown> {
  const iterations = boundedInteger(spec.iterations, 1, 20, "iterations");
  const warmup = boundedInteger(spec.warmup, 0, 10, "warmup");
  const { workload, phase } = parseFunction(spec.name);
  const benchmarkStarted = performance.now();
  setProgress(`Loading ${spec.name}`, benchmarkStarted);

  const [circuit, inputs, frozenWitness, frozenProofBytes, frozenPublicInputs] = await Promise.all([
    fetchJson<CircuitArtifact>(`./assets/${workload}/circuit.json`),
    fetchJson<Record<string, unknown>>(`./assets/${workload}/inputs.json`),
    fetchBytes(`./assets/${workload}/witness.gz`),
    fetchBytes(`./assets/${workload}/proof.bin`),
    fetchJson<string[]>(`./assets/${workload}/public-inputs.json`),
  ]);
  const noir = new Noir(circuit);
  const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1 });
  const backend = new UltraHonkBackend(circuit.bytecode, api);

  try {
    let preparedWitness = frozenWitness;
    let preparedProof: ProofData = {
      proof: frozenProofBytes,
      publicInputs: frozenPublicInputs,
    };
    if (phase === "witness" || phase === "e2e") {
      setProgress("Canary witness", benchmarkStarted);
      preparedWitness = (await noir.execute(inputs)).witness;
      setProgress("Canary proof", benchmarkStarted);
      preparedProof = (await backend.generateProof(preparedWitness)) as ProofData;
    } else if (phase === "prove") {
      setProgress("Canary proof from frozen witness", benchmarkStarted);
      preparedProof = (await backend.generateProof(preparedWitness)) as ProofData;
    }
    setProgress("Canary verification", benchmarkStarted);
    if (!(await backend.verifyProof(preparedProof))) {
      throw new Error(`Barretenberg rejected its ${workload} canary proof`);
    }
    setProgress("Tampered-proof verification", benchmarkStarted);
    const tamperedBytes = preparedProof.proof.slice();
    tamperedBytes[Math.floor(tamperedBytes.byteLength / 2)] ^= 1;
    let tamperedRejected = false;
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

    const samples: Array<{
      duration_ns: number;
      sample_index: number;
      warmup: boolean;
    }> = [];
    const timeline: Array<{
      phase: string;
      start_offset_ns: number;
      end_offset_ns: number;
      iteration: number | null;
    }> = [];
    const runStart = performance.now();

    for (let index = 0; index < warmup + iterations; index += 1) {
      const measured = index >= warmup;
      const iteration = measured ? index - warmup : null;
      const started = performance.now();
      setProgress(
        `${measured ? "Sample" : "Warmup"} ${index + 1}/${warmup + iterations}: ${phase}`,
        benchmarkStarted,
      );

      if (phase === "witness") {
        await noir.execute(inputs);
      } else if (phase === "prove") {
        await backend.generateProof(preparedWitness);
      } else if (phase === "verify") {
        if (!(await backend.verifyProof(preparedProof))) {
          throw new Error(`Barretenberg rejected ${workload} during verification sample`);
        }
      } else {
        const execution = await noir.execute(inputs);
        const proof = (await backend.generateProof(execution.witness)) as ProofData;
        if (!(await backend.verifyProof(proof))) {
          throw new Error(`Barretenberg rejected ${workload} during end-to-end sample`);
        }
      }

      const elapsed = durationNs(started);
      samples.push({
        duration_ns: elapsed,
        sample_index: measured ? index - warmup : index,
        warmup: !measured,
      });
      timeline.push({
        phase,
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
        backend: "barretenberg_4.2.0-aztecnr-rc.2_wasm_single",
        workload,
        phase,
        proof_size_bytes: preparedProof.proof.byteLength,
        public_input_count: preparedProof.publicInputs.length,
        tampered_proof_rejected: tamperedRejected,
        user_agent: navigator.userAgent,
        hardware_concurrency: navigator.hardwareConcurrency,
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
