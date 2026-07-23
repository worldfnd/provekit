export interface WasmProverHandle {
  getCircuit(): Uint8Array;
  getNumConstraints?(): number;
  getNumWitnesses?(): number;
  proveBytes(witness: Record<string, string>): Uint8Array;
  free(): void;
}

export interface WasmVerifierHandle {
  verifyBytes(proof: Uint8Array): boolean;
  free(): void;
}

export type WasmInitInput =
  | URL
  | RequestInfo
  | Response
  | BufferSource
  | WebAssembly.Module;

/** Structural type implemented by generated `provekit_wasm.js`. */
export interface ProveKitWasmModule {
  default(input?: { module_or_path?: WasmInitInput } | WasmInitInput): Promise<unknown>;
  initPanicHook?(): void;
  initThreadPool?(threads: number): Promise<unknown>;
  setWorkerUrl?(url: string): void;
  Prover: new (artifact: Uint8Array) => WasmProverHandle;
  Verifier: new (artifact: Uint8Array) => WasmVerifierHandle;
}

export type WasmModuleSource =
  | ProveKitWasmModule
  | Promise<ProveKitWasmModule>
  | (() => ProveKitWasmModule | Promise<ProveKitWasmModule>);

export type WasmVariant = "single" | "threaded";
