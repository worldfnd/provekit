export type ProvingInput = Record<string, unknown>;

export type BytesInput = Uint8Array | ArrayBuffer | ArrayBufferView | RequestInfo | URL | string;

export type ArtifactBaseUrl = string | URL;

export interface ArtifactBytes {
  baseUrl?: ArtifactBaseUrl;
  prover?: BytesInput;
  verifier?: BytesInput;
  /**
   * Set to `true` to skip loading a verifier artifact even when `baseUrl`
   * is provided. The resulting scheme can `prove()` but not `verify()`.
   */
  skipVerifier?: boolean;
}

export interface ProvingModules {
  /** Current Mavros artifact containing `mavros_main` and `mavros_ad_main`. */
  program?: BytesInput;
  /** Legacy split witness module. Must be paired with `derivatives`. */
  witness?: BytesInput;
  /** Legacy split derivatives module. Must be paired with `witness`. */
  derivatives?: BytesInput;
}

export type WasmModuleInput =
  | URL
  | Request
  | Response
  | BufferSource
  | WebAssembly.Module
  | Promise<URL | Request | Response | BufferSource | WebAssembly.Module>;

export type WasmInitFn = (moduleOrPath?: WasmModuleInput) => Promise<unknown>;

export interface ProveKitInitOptions {
  bindings: ProveKitWasmBindings;
  init?: WasmInitFn;
  wasmModule?: WasmModuleInput;
  threads?: number | false;
  panicHook?: boolean;
}

export interface LoadArtifactsOptions extends ArtifactBytes {
  provingModules?: ProvingModules;
  witnessProvider?: WitnessProvider;
}

export type LoadArtifactsInput = LoadArtifactsOptions | ArtifactBaseUrl;

export interface WitnessProvider {
  generateWitness(
    inputs: ProvingInput,
    circuit: unknown,
  ): Promise<Record<string, unknown> | Map<number | string, unknown>>;
}

export interface ProveKitWasmBindings {
  Prover: new (proverData: Uint8Array) => unknown;
  Verifier: new (verifierData: Uint8Array) => unknown;
  initPanicHook?: () => void;
  initThreadPool?: (numThreads: number) => Promise<unknown>;
}
