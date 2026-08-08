import { decompressWitness } from "@noir-lang/acvm_js";
import { Noir } from "@noir-lang/noir_js";
import initProveKitV1, {
  initPanicHook,
  Prover,
  Verifier,
} from "../v1-wasm-pkg/provekit_wasm.js";

interface RunCommand {
  type: "run";
  workload: WorkloadName;
  warmup: number;
  iterations: number;
  timing_mode?: "cold_local" | "warm_reuse";
}

type WorkloadName = "webauthn_assertion" | "passport_complete_age_check" | "passport_p1" | "oprf_taceo";

interface PhaseSample {
  iteration: number;
  warmup: boolean;
  prepare_time_ms: number;
  witness_time_ms: number;
  prove_time_ms: number;
  verify_time_ms: number;
  end_to_end_time_ms: number;
  input_to_proof_time_ms: number;
  proof_size_bytes: number;
  tampered_proof_rejected: boolean;
  js_heap_bytes?: number;
}

interface PerformanceWithMemory extends Performance {
  memory?: { usedJSHeapSize?: number };
}

interface BundleManifest {
  totals: Record<string, number>;
}

function elapsed(start: number): number {
  return performance.now() - start;
}

async function fetchBytes(path: string): Promise<Uint8Array> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`failed to fetch ${path}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function fetchJson<T extends object = Record<string, unknown>>(path: string): Promise<T> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`failed to fetch ${path}: HTTP ${response.status}`);
  return (await response.json()) as T;
}

async function fetchJsonSized<T extends object = Record<string, unknown>>(path: string) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`failed to fetch ${path}: HTTP ${response.status}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  return { value: JSON.parse(new TextDecoder().decode(bytes)) as T, bytes: bytes.byteLength };
}

function currentHeapBytes(): number | undefined {
  return (performance as PerformanceWithMemory).memory?.usedJSHeapSize;
}

async function runBenchmark(command: RunCommand): Promise<unknown> {
  const coldStarted = performance.now();
  const assetRoot = `/assets/${command.workload}`;
  const downloadStart = performance.now();
  const [pkp, pkv, sizedInputs, manifest] = await Promise.all([
    fetchBytes(`${assetRoot}/${command.workload}.pkp`),
    fetchBytes(`${assetRoot}/${command.workload}.pkv`),
    fetchJsonSized(`${assetRoot}/inputs.json`),
    fetchJson<BundleManifest>("/manifest.json"),
  ]);
  const inputs = sizedInputs.value;
  const downloadTimeMs = elapsed(downloadStart);
  const sharedRuntimeBytes = manifest.totals["shared-runtime"];
  const incrementalCircuitBytes = manifest.totals[command.workload];
  if (!Number.isSafeInteger(sharedRuntimeBytes) || !Number.isSafeInteger(incrementalCircuitBytes)) {
    throw new Error(`bundle manifest has no totals for ${command.workload}`);
  }

  const initStart = performance.now();
  await initProveKitV1();
  initPanicHook();
  const verifier = new Verifier(pkv);
  const initTimeMs = elapsed(initStart);

  const inspectionProver = new Prover(pkp);
  const circuitJson = JSON.parse(new TextDecoder().decode(inspectionProver.getCircuit())) as Record<string, unknown>;
  const constraints = inspectionProver.getNumConstraints();
  const witnesses = inspectionProver.getNumWitnesses();
  inspectionProver.free();
  const noir = new Noir(circuitJson);

  const samples: PhaseSample[] = [];
  for (let run = 0; run < command.warmup + command.iterations; run += 1) {
    const endToEndStart = command.timing_mode === "cold_local" && run === 0
      ? coldStarted
      : performance.now();
    const prepareStart = performance.now();
    const prover = new Prover(pkp);
    const prepareTimeMs = elapsed(prepareStart);

    const witnessStart = performance.now();
    const execution = await noir.execute(inputs);
    const witnessMap = decompressWitness(execution.witness);
    const witnessTimeMs = elapsed(witnessStart);
    const proveStart = performance.now();
    const proof = prover.proveBytes(witnessMap);
    const proveTimeMs = elapsed(proveStart);
    const inputToProofTimeMs = elapsed(endToEndStart);
    prover.free();

    const verifyStart = performance.now();
    verifier.verifyBytes(proof);
    const verifyTimeMs = elapsed(verifyStart);
    const tamperedProof = proof.slice();
    tamperedProof[Math.floor(tamperedProof.byteLength / 2)] ^= 1;
    let tamperedProofRejected = false;
    try {
      verifier.verifyBytes(tamperedProof);
    } catch {
      tamperedProofRejected = true;
    }
    if (!tamperedProofRejected) throw new Error(`ProveKit accepted a tampered ${command.workload} proof`);

    samples.push({
      iteration: run < command.warmup ? run : run - command.warmup,
      warmup: run < command.warmup,
      prepare_time_ms: command.timing_mode === "cold_local" && run === 0
        ? inputToProofTimeMs - witnessTimeMs - proveTimeMs
        : prepareTimeMs,
      witness_time_ms: witnessTimeMs,
      prove_time_ms: proveTimeMs,
      verify_time_ms: verifyTimeMs,
      end_to_end_time_ms: elapsed(endToEndStart),
      input_to_proof_time_ms: inputToProofTimeMs,
      proof_size_bytes: proof.byteLength,
      tampered_proof_rejected: tamperedProofRejected,
      js_heap_bytes: currentHeapBytes(),
    });
  }
  verifier.free();

  return {
    schema_version: 1,
    benchmark: command.workload,
    backend: "provekit_v1_branch_9b2a6f_wasm_single",
    download_time_ms: downloadTimeMs,
    initialization_time_ms: initTimeMs,
    artifacts: {
      prover_bytes: pkp.byteLength,
      verifier_bytes: pkv.byteLength,
      input_bytes: sizedInputs.bytes,
      proving_payload_size_bytes: pkp.byteLength + sizedInputs.bytes,
    },
    bundle: {
      shared_runtime_bytes: sharedRuntimeBytes,
      incremental_circuit_bytes: incrementalCircuitBytes,
      cold_download_bytes: sharedRuntimeBytes + incrementalCircuitBytes,
    },
    circuit: { constraints, witnesses },
    environment: {
      user_agent: navigator.userAgent,
      hardware_concurrency: navigator.hardwareConcurrency,
      cross_origin_isolated: self.crossOriginIsolated,
      wasm_threads: false,
      memory_metric: currentHeapBytes() === undefined ? "unavailable" : "chromium-used-js-heap-not-process-rss",
    },
    warmup: command.warmup,
    iterations: command.iterations,
    timing_mode: command.timing_mode ?? "warm_reuse",
    samples,
  };
}

self.addEventListener("message", async (event: MessageEvent<RunCommand>) => {
  if (event.data.type !== "run") return;
  try {
    self.postMessage({ type: "complete", result: await runBenchmark(event.data) });
  } catch (error) {
    const details: string[] = [];
    let current: unknown = error;
    while (current instanceof Error) {
      details.push(`${current.name}: ${current.message}\n${current.stack ?? ""}`);
      current = current.cause;
    }
    if (current !== undefined) details.push(String(current));
    self.postMessage({ type: "error", error: details.join("\nCaused by:\n") || String(error) });
  }
});
