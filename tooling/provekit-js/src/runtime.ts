import {
  type ArtifactLimits,
  normalizeLimits,
  preflightArtifact,
} from "./artifacts.js";
import { ProveKitError, ProveKitErrorCode, mapRuntimeError } from "./errors.js";
import { ProveKitProver, ProveKitVerifier, type Prover, type Verifier } from "./schemes.js";
import { resolveWasmModule } from "./wasm-loader.js";
import type {
  ProveKitWasmModule,
  WasmInitInput,
  WasmModuleSource,
  WasmVariant,
} from "./wasm-types.js";

export type ThreadSetting = "auto" | false | number;

export interface InitProveKitOptions {
  threads?: ThreadSetting;
  /** Override the generated JS glue module or its loader. */
  wasmModule?: WasmModuleSource;
  /** Override the binary/module input passed to wasm-bindgen initialization. */
  wasmUrl?: WasmInitInput;
  limits?: Partial<ArtifactLimits>;
}

export interface ThreadingStatus {
  mode: "single" | "threaded";
  threads: number;
  fallbackReason?: string;
}

export interface CircuitStats {
  constraints?: number;
  witnesses?: number;
}

export interface ProveKitRuntime {
  readonly threading: ThreadingStatus;
  loadProver(artifact: Uint8Array): Promise<Prover>;
  loadVerifier(artifact: Uint8Array): Promise<Verifier>;
  inspectProver(artifact: Uint8Array): CircuitStats;
}

interface NormalizedOptions {
  threads: ThreadSetting;
  wasmModule?: WasmModuleSource;
  wasmUrl?: WasmInitInput;
  limits: ArtifactLimits;
}

let initialized: { options: NormalizedOptions; runtime: ProveKitRuntime } | null = null;
let pending: { options: NormalizedOptions; promise: Promise<ProveKitRuntime> } | null = null;

function normalizeOptions(options: InitProveKitOptions): NormalizedOptions {
  const threads = options.threads ?? "auto";
  if (
    threads !== "auto" &&
    threads !== false &&
    (!Number.isSafeInteger(threads) || threads <= 0 || threads > 255)
  ) {
    throw new ProveKitError(
      ProveKitErrorCode.INVALID_ARGUMENT,
      "threads must be 'auto', false, or an integer from 1 through 255",
    );
  }
  const normalized: NormalizedOptions = {
    threads,
    limits: normalizeLimits(options.limits),
  };
  if (options.wasmModule !== undefined) normalized.wasmModule = options.wasmModule;
  if (options.wasmUrl !== undefined) normalized.wasmUrl = options.wasmUrl;
  return normalized;
}

function equalOptions(left: NormalizedOptions, right: NormalizedOptions): boolean {
  return left.threads === right.threads &&
    left.wasmModule === right.wasmModule &&
    left.wasmUrl === right.wasmUrl &&
    left.limits.maxProverBytes === right.limits.maxProverBytes &&
    left.limits.maxVerifierBytes === right.limits.maxVerifierBytes &&
    left.limits.maxProofBytes === right.limits.maxProofBytes;
}

function assertCompatible(existing: NormalizedOptions, requested: NormalizedOptions): void {
  if (!equalOptions(existing, requested)) {
    throw new ProveKitError(
      ProveKitErrorCode.INITIALIZATION_CONFLICT,
      "ProveKit is already initializing or initialized with different global options",
    );
  }
}

function browserThreadCapability(): { available: true; suggestedThreads: number } | { available: false; reason: string } {
  if (typeof window === "undefined" || typeof navigator === "undefined") {
    return { available: false, reason: "WASM workers are unavailable outside a browser" };
  }
  if (typeof SharedArrayBuffer === "undefined") {
    return { available: false, reason: "SharedArrayBuffer is unavailable" };
  }
  if (globalThis.crossOriginIsolated !== true) {
    return { available: false, reason: "The page is not cross-origin isolated (COOP/COEP required)" };
  }
  const navigatorWithPlatform = navigator as Navigator & { platform?: string; maxTouchPoints?: number };
  const isiOS = /iPhone|iPad|iPod/.test(navigator.userAgent) ||
    (navigatorWithPlatform.platform === "MacIntel" && (navigatorWithPlatform.maxTouchPoints ?? 0) > 1);
  if (isiOS) {
    return { available: false, reason: "iOS/iPadOS WebKit uses single-threaded proving" };
  }
  return {
    available: true,
    suggestedThreads: Math.max(1, Math.min(8, navigator.hardwareConcurrency || 4)),
  };
}

interface ThreadPlan {
  variant: WasmVariant;
  threadCount: number;
  fallbackReason?: string;
}

function planThreads(
  setting: ThreadSetting,
): ThreadPlan {
  if (setting === false) return { variant: "single", threadCount: 1 };

  const capability = browserThreadCapability();
  if (!capability.available) {
    if (setting !== "auto") {
      throw new ProveKitError(ProveKitErrorCode.THREADS_UNAVAILABLE, capability.reason);
    }
    return { variant: "single", threadCount: 1, fallbackReason: capability.reason };
  }

  return {
    variant: "threaded",
    threadCount: setting === "auto" ? capability.suggestedThreads : setting,
  };
}

async function initializeModule(
  module: ProveKitWasmModule,
  wasmUrl?: WasmInitInput,
): Promise<void> {
  if (wasmUrl === undefined) await module.default();
  else await module.default({ module_or_path: wasmUrl });
  module.initPanicHook?.();
}

class Runtime implements ProveKitRuntime {
  constructor(
    private readonly module: ProveKitWasmModule,
    readonly threading: ThreadingStatus,
    private readonly limits: ArtifactLimits,
  ) {}

  async loadProver(artifact: Uint8Array): Promise<Prover> {
    if (!(artifact instanceof Uint8Array)) {
      throw new ProveKitError(ProveKitErrorCode.INVALID_ARGUMENT, "Prover artifact must be a Uint8Array");
    }
    preflightArtifact(artifact, "prover", this.limits);
    let handle: InstanceType<ProveKitWasmModule["Prover"]> | undefined;
    try {
      handle = new this.module.Prover(artifact);
      const circuitBytes = handle.getCircuit();
      const circuit: unknown = JSON.parse(new TextDecoder().decode(circuitBytes));
      return new ProveKitProver(this.module, artifact, circuit, this.limits);
    } catch (error) {
      throw mapRuntimeError(error, ProveKitErrorCode.ARTIFACT_FORMAT, "Failed to load prover artifact");
    } finally {
      handle?.free();
    }
  }

  async loadVerifier(artifact: Uint8Array): Promise<Verifier> {
    if (!(artifact instanceof Uint8Array)) {
      throw new ProveKitError(ProveKitErrorCode.INVALID_ARGUMENT, "Verifier artifact must be a Uint8Array");
    }
    preflightArtifact(artifact, "verifier", this.limits);
    try {
      return new ProveKitVerifier(new this.module.Verifier(artifact), artifact, this.limits);
    } catch (error) {
      throw mapRuntimeError(error, ProveKitErrorCode.ARTIFACT_FORMAT, "Failed to load verifier artifact");
    }
  }

  inspectProver(artifact: Uint8Array): CircuitStats {
    preflightArtifact(artifact, "prover", this.limits);
    let handle: InstanceType<ProveKitWasmModule["Prover"]> | undefined;
    try {
      handle = new this.module.Prover(artifact);
      const result: CircuitStats = {};
      if (handle.getNumConstraints) result.constraints = handle.getNumConstraints();
      if (handle.getNumWitnesses) result.witnesses = handle.getNumWitnesses();
      return result;
    } catch (error) {
      throw mapRuntimeError(error, ProveKitErrorCode.ARTIFACT_FORMAT, "Failed to inspect prover artifact");
    } finally {
      handle?.free();
    }
  }
}

async function initialize(options: NormalizedOptions): Promise<ProveKitRuntime> {
  try {
    const plan = planThreads(options.threads);
    let module = await resolveWasmModule(options.wasmModule, plan.variant);
    await initializeModule(module, options.wasmUrl);

    if (plan.variant === "single") {
      const threading: ThreadingStatus = { mode: "single", threads: 1 };
      if (plan.fallbackReason !== undefined) threading.fallbackReason = plan.fallbackReason;
      return new Runtime(module, threading, options.limits);
    }

    if (module.initThreadPool) {
      try {
        await module.initThreadPool(plan.threadCount);
        return new Runtime(
          module,
          { mode: "threaded", threads: plan.threadCount },
          options.limits,
        );
      } catch (error) {
        if (options.threads !== "auto" || options.wasmModule || options.wasmUrl) {
          throw new ProveKitError(
            ProveKitErrorCode.THREADS_UNAVAILABLE,
            `Failed to initialize ${plan.threadCount} WASM workers`,
            { cause: error },
          );
        }
        module = await resolveWasmModule(undefined, "single");
        await initializeModule(module);
        return new Runtime(
          module,
          {
            mode: "single",
            threads: 1,
            fallbackReason: `WASM worker initialization failed: ${error instanceof Error ? error.message : String(error)}`,
          },
          options.limits,
        );
      }
    }

    if (options.threads !== "auto") {
      throw new ProveKitError(
        ProveKitErrorCode.THREADS_UNAVAILABLE,
        "The selected WASM module has no thread-pool initializer",
      );
    }
    return new Runtime(
      module,
      {
        mode: "single",
        threads: 1,
        fallbackReason: "The selected WASM module has no thread-pool initializer",
      },
      options.limits,
    );
  } catch (error) {
    if (error instanceof ProveKitError) throw error;
    throw mapRuntimeError(
      error,
      ProveKitErrorCode.INITIALIZATION_FAILED,
      "Failed to initialize ProveKit WASM",
    );
  }
}

/** Initializes the process/page-wide ProveKit WASM runtime exactly once. */
export async function initProveKit(options: InitProveKitOptions = {}): Promise<ProveKitRuntime> {
  const normalized = normalizeOptions(options);
  if (initialized) {
    assertCompatible(initialized.options, normalized);
    return initialized.runtime;
  }
  if (pending) {
    assertCompatible(pending.options, normalized);
    return pending.promise;
  }

  const promise = initialize(normalized)
    .then((runtime) => {
      initialized = { options: normalized, runtime };
      pending = null;
      return runtime;
    })
    .catch((error: unknown) => {
      pending = null;
      throw error;
    });
  pending = { options: normalized, promise };
  return promise;
}

/** @internal Test isolation only; a page cannot tear down wasm-bindgen-rayon. */
export function resetInitializationForTests(): void {
  initialized = null;
  pending = null;
}
