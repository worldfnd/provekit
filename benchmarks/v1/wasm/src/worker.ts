import { initProveKit, Proof } from "@worldcoin/provekit";

interface RunCommand {
  type: "run";
  workload: WorkloadName;
  warmup: number;
  iterations: number;
}

type WorkloadName =
  | "webauthn_assertion"
  | "passport_complete_age_check"
  | "oprf_taceo";

interface PhaseSample {
  iteration: number;
  warmup: boolean;
  prepare_time_ms: number;
  witness_time_ms?: number;
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

function currentHeapBytes(): number | undefined {
  return (performance as PerformanceWithMemory).memory?.usedJSHeapSize;
}

async function runBenchmark(command: RunCommand): Promise<unknown> {
  const assetRoot = `/assets/${command.workload}`;
  const downloadStart = performance.now();
  const [pkp, pkv, inputs, manifest] = await Promise.all([
    fetchBytes(`${assetRoot}/${command.workload}.pkp`),
    fetchBytes(`${assetRoot}/${command.workload}.pkv`),
    fetchJson(`${assetRoot}/inputs.json`),
    fetchJson<BundleManifest>("/manifest.json"),
  ]);
  const downloadTimeMs = elapsed(downloadStart);
  const sharedRuntimeBytes = manifest.totals["shared-runtime"];
  const incrementalCircuitBytes = manifest.totals[command.workload];
  if (
    !Number.isSafeInteger(sharedRuntimeBytes) ||
    !Number.isSafeInteger(incrementalCircuitBytes)
  ) {
    throw new Error(`bundle manifest has no totals for ${command.workload}`);
  }

  const initStart = performance.now();
  const runtime = await initProveKit({ threads: false });
  if (runtime.threading.mode !== "single") {
    throw new Error("browser benchmark requires the single-thread ProveKit runtime");
  }
  const verifier = await runtime.loadVerifier(pkv);
  const initTimeMs = elapsed(initStart);

  const circuit = runtime.inspectProver(pkp);

  const samples: PhaseSample[] = [];
  const totalRuns = command.warmup + command.iterations;
  for (let run = 0; run < totalRuns; run += 1) {
    const endToEndStart = performance.now();

    const prepareStart = performance.now();
    const prover = await runtime.loadProver(pkp);
    const prepareTimeMs = elapsed(prepareStart);

    const witnessStart = performance.now();
    // The public SDK intentionally owns ACVM witness generation. It does not
    // expose a separate witness-only API, so this campaign records the SDK
    // prove call as end-to-end proving and leaves witness_time_ms blank.
    const proveStart = witnessStart;
    const proof = await prover.prove(inputs);
    const proveTimeMs = elapsed(proveStart);
    const witnessTimeMs = Number.NaN;
    prover.dispose();

    const verifyStart = performance.now();
    if (!(await verifier.verify(proof))) {
      throw new Error(`ProveKit rejected its ${command.workload} proof`);
    }
    const verifyTimeMs = elapsed(verifyStart);

    const tamperedProof = proof.bytes;
    tamperedProof[Math.floor(tamperedProof.byteLength / 2)] ^= 1;
    let tamperedProofRejected = false;
    try {
      tamperedProofRejected = !(await verifier.verify(Proof.fromBytes(tamperedProof)));
    } catch {
      tamperedProofRejected = true;
    }
    if (!tamperedProofRejected) {
      throw new Error(`ProveKit accepted a tampered ${command.workload} proof`);
    }

    samples.push({
      iteration: run < command.warmup ? run : run - command.warmup,
      warmup: run < command.warmup,
      prepare_time_ms: prepareTimeMs,
      witness_time_ms: Number.isNaN(witnessTimeMs) ? undefined : witnessTimeMs,
      prove_time_ms: proveTimeMs,
      verify_time_ms: verifyTimeMs,
      end_to_end_time_ms: elapsed(endToEndStart),
      proof_size_bytes: proof.size,
      tampered_proof_rejected: tamperedProofRejected,
      js_heap_bytes: currentHeapBytes(),
    });
  }

  verifier.dispose();

  return {
    schema_version: 1,
    benchmark: command.workload,
    backend: "provekit_v1_wasm_single",
    download_time_ms: downloadTimeMs,
    initialization_time_ms: initTimeMs,
    artifacts: {
      prover_bytes: pkp.byteLength,
      verifier_bytes: pkv.byteLength,
    },
    bundle: {
      shared_runtime_bytes: sharedRuntimeBytes,
      incremental_circuit_bytes: incrementalCircuitBytes,
      cold_download_bytes: sharedRuntimeBytes + incrementalCircuitBytes,
    },
    circuit: {
      constraints: circuit.constraints,
      witnesses: circuit.witnesses,
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
    const details: string[] = [];
    let current: unknown = error;
    while (current instanceof Error) {
      details.push(`${current.name}: ${current.message}\n${current.stack ?? ""}`);
      current = current.cause;
    }
    if (current !== undefined) details.push(String(current));
    self.postMessage({
      type: "error",
      error: details.length > 0 ? details.join("\nCaused by:\n") : String(error),
    });
  }
});
