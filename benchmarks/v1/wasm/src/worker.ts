import { decompressWitnessStack } from "@noir-lang/acvm_js";
import { Noir } from "@noir-lang/noir_js";
import initProveKit, {
  initPanicHook,
  Prover,
  supportsThreads,
  Verifier,
} from "../generated/provekit/provekit_wasm.js";

interface RunCommand {
  type: "run";
  warmup: number;
  iterations: number;
}

interface PhaseSample {
  iteration: number;
  warmup: boolean;
  prepare_time_ms: number;
  witness_time_ms: number;
  prove_time_ms: number;
  verify_time_ms: number;
  end_to_end_time_ms: number;
  proof_size_bytes: number;
  tampered_proof_rejected: boolean;
  js_heap_bytes?: number;
}

interface PerformanceWithMemory extends Performance {
  memory?: {
    usedJSHeapSize?: number;
  };
}

function elapsed(start: number): number {
  return performance.now() - start;
}

function normalizeWitnessMap(value: unknown): Record<string, string> {
  if (!(value instanceof Map)) throw new Error("ACVM witness stack did not contain a Map");

  const output: Record<string, string> = {};
  for (const [rawKey, rawValue] of value) {
    const key =
      typeof rawKey === "number" || typeof rawKey === "string"
        ? String(rawKey)
        : typeof rawKey === "object" && rawKey !== null && "inner" in rawKey
          ? String((rawKey as { inner: unknown }).inner)
          : null;
    if (key === null || !/^\d+$/.test(key)) throw new Error("invalid Noir witness key");
    if (typeof rawValue !== "string") throw new Error(`witness ${key} is not a field string`);
    output[key] = rawValue;
  }
  return output;
}

async function fetchBytes(path: string): Promise<Uint8Array> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`failed to fetch ${path}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function fetchJson(path: string): Promise<Record<string, unknown>> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`failed to fetch ${path}: HTTP ${response.status}`);
  return (await response.json()) as Record<string, unknown>;
}

function currentHeapBytes(): number | undefined {
  return (performance as PerformanceWithMemory).memory?.usedJSHeapSize;
}

async function runBenchmark(command: RunCommand): Promise<unknown> {
  const downloadStart = performance.now();
  const [pkp, pkv, inputs] = await Promise.all([
    fetchBytes("./assets/webauthn_assertion.pkp"),
    fetchBytes("./assets/webauthn_assertion.pkv"),
    fetchJson("./assets/inputs.json"),
  ]);
  const downloadTimeMs = elapsed(downloadStart);

  const initStart = performance.now();
  await initProveKit();
  initPanicHook();
  if (supportsThreads()) throw new Error("browser benchmark requires the single-thread WASM build");
  const verifier = new Verifier(pkv);
  const initTimeMs = elapsed(initStart);

  const circuitProver = new Prover(pkp);
  const constraints = circuitProver.getNumConstraints();
  const witnesses = circuitProver.getNumWitnesses();
  const circuit = JSON.parse(new TextDecoder().decode(circuitProver.getCircuit())) as object;
  circuitProver.free();
  const noir = new Noir(circuit);

  const samples: PhaseSample[] = [];
  const totalRuns = command.warmup + command.iterations;
  for (let run = 0; run < totalRuns; run += 1) {
    const endToEndStart = performance.now();

    const prepareStart = performance.now();
    const prover = new Prover(pkp);
    const prepareTimeMs = elapsed(prepareStart);

    const witnessStart = performance.now();
    const execution = await noir.execute(inputs);
    const stack = decompressWitnessStack(execution.witness) as unknown;
    if (!Array.isArray(stack) || stack.length === 0) throw new Error("ACVM returned no witness");
    const witness = normalizeWitnessMap((stack[0] as { witness?: unknown }).witness);
    const witnessTimeMs = elapsed(witnessStart);

    const proveStart = performance.now();
    const proof = prover.proveBytes(witness);
    const proveTimeMs = elapsed(proveStart);
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
    if (!tamperedProofRejected) {
      throw new Error("ProveKit accepted a tampered WebAuthn proof");
    }

    samples.push({
      iteration: run < command.warmup ? run : run - command.warmup,
      warmup: run < command.warmup,
      prepare_time_ms: prepareTimeMs,
      witness_time_ms: witnessTimeMs,
      prove_time_ms: proveTimeMs,
      verify_time_ms: verifyTimeMs,
      end_to_end_time_ms: elapsed(endToEndStart),
      proof_size_bytes: proof.byteLength,
      tampered_proof_rejected: tamperedProofRejected,
      js_heap_bytes: currentHeapBytes(),
    });
  }

  verifier.free();
  const destroy = (noir as Noir & { destroy?: () => Promise<void> | void }).destroy;
  if (destroy) await destroy.call(noir);

  return {
    schema_version: 1,
    benchmark: "webauthn_assertion",
    backend: "provekit_v1_wasm_single",
    download_time_ms: downloadTimeMs,
    initialization_time_ms: initTimeMs,
    artifacts: {
      prover_bytes: pkp.byteLength,
      verifier_bytes: pkv.byteLength,
    },
    circuit: {
      constraints,
      witnesses,
    },
    environment: {
      user_agent: navigator.userAgent,
      hardware_concurrency: navigator.hardwareConcurrency,
      cross_origin_isolated: self.crossOriginIsolated,
      wasm_threads: false,
      memory_metric:
        currentHeapBytes() === undefined ? "unavailable" : "chromium-used-js-heap-not-process-rss",
    },
    warmup: command.warmup,
    iterations: command.iterations,
    samples,
  };
}

self.addEventListener("message", async (event: MessageEvent<RunCommand>) => {
  if (event.data.type !== "run") return;
  try {
    const result = await runBenchmark(event.data);
    self.postMessage({ type: "complete", result });
  } catch (error) {
    self.postMessage({
      type: "error",
      error: error instanceof Error ? `${error.message}\n${error.stack ?? ""}` : String(error),
    });
  }
});
