/* tslint:disable */
/* eslint-disable */
export function initPanicHook(): void;
export function initThreadPool(num_threads: number): Promise<any>;
export function wbg_rayon_start_worker(receiver: number): void;
/**
 * WASM bindings for proof generation. Consumed after `proveBytes`/`proveJs`.
 */
export class Prover {
  free(): void;
  /**
   * Returns circuit JSON for `@noir-lang/noir_js`.
   *
   * ```js
   * const prover = new Prover(pkpBytes);
   * const circuitJson = JSON.parse(new TextDecoder().decode(prover.getCircuit()));
   * const noir = new Noir(circuitJson);
   * ```
   */
  getCircuit(): Uint8Array;
  /**
   * `witness_map`: JS `Map<number, string>` or plain object `{ "0": "0xhex…"
   * }`.
   */
  proveBytes(witness_map: any): Uint8Array;
  getProverKind(): string;
  proveMavrosJs(inputs: any, runner: any): any;
  getNumWitnesses(): number;
  /**
   * Generates a proof for Mavros provers using browser-side Mavros WASM
   * artifacts.
   *
   * `inputs` is the regular ABI-shaped input object. `runner` must expose
   * synchronous `runWitgen(inputBytes, witnessLayout, constraintsLayout)`
   * and `runAd(coeffBytes, witnessLayout, constraintsLayout)` methods.
   */
  proveMavrosBytes(inputs: any, runner: any): Uint8Array;
  getNumConstraints(): number;
  constructor(prover_data: Uint8Array);
  proveJs(witness_map: any): any;
}
/**
 * WASM bindings for proof verification. Reusable across multiple proofs.
 */
export class Verifier {
  free(): void;
  /**
   * Verifies a proof provided as JSON bytes. The verifier is **not**
   * consumed.
   */
  verifyBytes(proof_json: Uint8Array): void;
  /**
   * Creates a new verifier from a `.pkv` verifier artifact.
   */
  constructor(verifier_data: Uint8Array);
  /**
   * Verifies a proof provided as a JavaScript object. The verifier is
   * **not** consumed.
   */
  verifyJs(proof: any): void;
}
export class wbg_rayon_PoolBuilder {
  private constructor();
  free(): void;
  numThreads(): number;
  build(): void;
  receiver(): number;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly __wbg_prover_free: (a: number, b: number) => void;
  readonly __wbg_verifier_free: (a: number, b: number) => void;
  readonly prover_getCircuit: (a: number) => [number, number, number, number];
  readonly prover_getNumConstraints: (a: number) => [number, number, number];
  readonly prover_getNumWitnesses: (a: number) => [number, number, number];
  readonly prover_getProverKind: (a: number) => [number, number, number, number];
  readonly prover_new: (a: number, b: number) => [number, number, number];
  readonly prover_proveBytes: (a: number, b: number) => [number, number, number, number];
  readonly prover_proveJs: (a: number, b: number) => [number, number, number];
  readonly prover_proveMavrosBytes: (a: number, b: number, c: number) => [number, number, number, number];
  readonly prover_proveMavrosJs: (a: number, b: number, c: number) => [number, number, number];
  readonly verifier_new: (a: number, b: number) => [number, number, number];
  readonly verifier_verifyBytes: (a: number, b: number, c: number) => [number, number];
  readonly verifier_verifyJs: (a: number, b: number) => [number, number];
  readonly initPanicHook: () => void;
  readonly __wbg_wbg_rayon_poolbuilder_free: (a: number, b: number) => void;
  readonly initThreadPool: (a: number) => number;
  readonly wbg_rayon_poolbuilder_build: (a: number) => void;
  readonly wbg_rayon_poolbuilder_numThreads: (a: number) => number;
  readonly wbg_rayon_poolbuilder_receiver: (a: number) => number;
  readonly wbg_rayon_start_worker: (a: number) => void;
  readonly memory: WebAssembly.Memory;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly wasm_bindgen_66b12b5a02f6ae0a___convert__closures__invoke2_mut___wasm_bindgen_66b12b5a02f6ae0a___JsValue__wasm_bindgen_66b12b5a02f6ae0a___JsValue_____: (a: number, b: number, c: number, d: number) => void;
  readonly __wbindgen_thread_destroy: (a?: number, b?: number, c?: number) => void;
  readonly __wbindgen_start: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number }} module - Passing `SyncInitInput` directly is deprecated.
* @param {WebAssembly.Memory} memory - Deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number } | SyncInitInput, memory?: WebAssembly.Memory): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number }} module_or_path - Passing `InitInput` directly is deprecated.
* @param {WebAssembly.Memory} memory - Deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number } | InitInput | Promise<InitInput>, memory?: WebAssembly.Memory): Promise<InitOutput>;
