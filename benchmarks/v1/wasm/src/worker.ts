import { decompressWitness } from "@noir-lang/acvm_js";
import { Noir } from "@noir-lang/noir_js";
import initProveKitV1, {
  initPanicHook,
  initThreadPool,
  Prover,
  Verifier,
} from "../v1-wasm-pkg/provekit_wasm.js";

type ThreadRequest = "single" | "auto" | number;

interface RunCommand {
  type: "run";
  workload: WorkloadName;
  warmup: number;
  iterations: number;
  timing_mode?: "cold_local" | "warm_reuse";
  /**
   * `single` preserves the historical V1 measurement. `auto` uses a bounded
   * worker pool when the page is cross-origin isolated; a numeric value is a
   * strict request and fails instead of silently becoming a single-thread
   * measurement when the browser cannot share WASM memory.
   */
  wasm_threads?: ThreadRequest;
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

interface ThreadRuntime {
  request: ThreadRequest;
  requested_threads: number;
  wasm_threads: boolean;
  wasm_thread_count: number;
  wasm_thread_mode: "single" | "rayon_threaded" | "fallback_single";
  cross_origin_isolated: boolean;
  shared_array_buffer: boolean;
  init_thread_pool_available: boolean;
  hardware_concurrency?: number;
  fallback_reason?: string;
}

let runtimeInitialization: Promise<void> | undefined;
let threadRuntime: ThreadRuntime | undefined;

function threadCapabilities() {
  const hardwareConcurrency =
    typeof navigator === "undefined" || !Number.isInteger(navigator.hardwareConcurrency)
      ? undefined
      : navigator.hardwareConcurrency;
  return {
    crossOriginIsolated: self.crossOriginIsolated === true,
    sharedArrayBuffer: typeof SharedArrayBuffer !== "undefined",
    initThreadPoolAvailable: typeof initThreadPool === "function",
    hardwareConcurrency,
  };
}

function requestedThreadCount(request: ThreadRequest): number {
  if (request === "single") return 1;
  if (request === "auto") {
    // Keep the browser campaign deterministic while avoiding an unbounded pool
    // on high-core-count hosts. A browser that reports one core remains scalar.
    const hardwareConcurrency = threadCapabilities().hardwareConcurrency ?? 4;
    return hardwareConcurrency <= 1 ? 1 : Math.min(8, hardwareConcurrency);
  }
  if (!Number.isInteger(request) || request < 2 || request > 32) {
    throw new Error("wasm_threads must be `single`, `auto`, or an integer from 2 to 32");
  }
  return request;
}

async function initializeRuntime(request: ThreadRequest): Promise<ThreadRuntime> {
  if (!runtimeInitialization) {
    runtimeInitialization = (async () => {
      await initProveKitV1();
      initPanicHook();
    })();
  }
  await runtimeInitialization;

  const requestedThreads = requestedThreadCount(request);
  const capabilities = threadCapabilities();
  const canUseThreads =
    requestedThreads > 1 &&
    capabilities.crossOriginIsolated &&
    capabilities.sharedArrayBuffer &&
    capabilities.initThreadPoolAvailable;

  if (threadRuntime) {
    // wasm-bindgen-rayon owns one global pool per module. Do not allow a page
    // to report a different thread policy after the pool has been initialized.
    if (threadRuntime.wasm_thread_count !== (canUseThreads ? requestedThreads : 1)) {
      throw new Error("WASM thread policy cannot change after runtime initialization");
    }
    return threadRuntime;
  }

  if (requestedThreads > 1 && !canUseThreads && request !== "auto") {
    const reasons = [
      !capabilities.crossOriginIsolated && "crossOriginIsolated is false",
      !capabilities.sharedArrayBuffer && "SharedArrayBuffer is unavailable",
      !capabilities.initThreadPoolAvailable && "the WASM module has no initThreadPool export",
    ].filter(Boolean);
    throw new Error(`threaded WASM requested but unavailable (${reasons.join(", ")})`);
  }

  if (canUseThreads) {
    await initThreadPool(requestedThreads);
    threadRuntime = {
      request,
      requested_threads: requestedThreads,
      wasm_threads: true,
      wasm_thread_count: requestedThreads,
      wasm_thread_mode: "rayon_threaded",
      cross_origin_isolated: capabilities.crossOriginIsolated,
      shared_array_buffer: capabilities.sharedArrayBuffer,
      init_thread_pool_available: capabilities.initThreadPoolAvailable,
      hardware_concurrency: capabilities.hardwareConcurrency,
    };
    return threadRuntime;
  }

  threadRuntime = {
    request,
    requested_threads: requestedThreads,
    wasm_threads: false,
    wasm_thread_count: 1,
    wasm_thread_mode: request === "auto" && requestedThreads > 1 ? "fallback_single" : "single",
    cross_origin_isolated: capabilities.crossOriginIsolated,
    shared_array_buffer: capabilities.sharedArrayBuffer,
    init_thread_pool_available: capabilities.initThreadPoolAvailable,
    hardware_concurrency: capabilities.hardwareConcurrency,
    ...(request === "auto" && requestedThreads > 1
      ? {
          fallback_reason: [
            !capabilities.crossOriginIsolated && "crossOriginIsolated is false",
            !capabilities.sharedArrayBuffer && "SharedArrayBuffer is unavailable",
            !capabilities.initThreadPoolAvailable && "the WASM module has no initThreadPool export",
          ]
            .filter(Boolean)
            .join(", "),
        }
      : {}),
  };
  return threadRuntime;
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
  const runtime = await initializeRuntime(command.wasm_threads ?? "single");
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
    backend: `provekit_v1_branch_9b2a6f_wasm_${runtime.wasm_thread_mode}`,
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
      cross_origin_isolated: runtime.cross_origin_isolated,
      shared_array_buffer: runtime.shared_array_buffer,
      init_thread_pool_available: runtime.init_thread_pool_available,
      wasm_threads: runtime.wasm_threads,
      wasm_thread_count: runtime.wasm_thread_count,
      wasm_thread_mode: runtime.wasm_thread_mode,
      wasm_thread_request: runtime.request,
      ...(runtime.fallback_reason ? { wasm_thread_fallback_reason: runtime.fallback_reason } : {}),
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
