/* tslint:disable */
/* eslint-disable */
/**
 * Initializes panic hook to forward Rust panics to the browser console.
 *
 * Call this once when your WASM module loads to get better error messages
 * in the browser developer tools. This function is idempotent and can be
 * called multiple times safely.
 */
export function initPanicHook(): void;
export function initThreadPool(num_threads: number): Promise<any>;
export function wbg_rayon_start_worker(receiver: number): void;
/**
 * A prover instance for generating zero-knowledge proofs in WebAssembly.
 *
 * This struct wraps a ProveKit prover and provides methods to generate proofs
 * from witness data. Create an instance using the JSON-encoded prover
 * artifact.
 */
export class Prover {
  free(): void;
  /**
   * Generates a proof from a witness map and returns it as JSON bytes.
   *
   * Use this method after generating the witness using Noir's JavaScript
   * library. The witness map should be a JavaScript Map or object
   * mapping witness indices to hex-encoded field element strings.
   *
   * # Arguments
   *
   * * `witness_map` - JavaScript Map or object: `Map<number, string>` or `{
   *   [index: number]: string }` where strings are hex-encoded field
   *   elements
   *
   * # Returns
   *
   * A `Uint8Array` containing the JSON-encoded proof.
   *
   * # Errors
   *
   * Returns an error if the witness map cannot be parsed or proof generation
   * fails.
   *
   * # Example
   *
   * ```javascript
   * import { generateWitness } from '@noir-lang/noir_js';
   * import { Prover } from './pkg/provekit_wasm.js';
   *
   * const witnessStack = await generateWitness(compiledProgram, inputs);
   * const prover = new Prover(proverJson);
   * // Use the witness from the last stack item
   * // Note: prover is consumed after this call (single-use for memory efficiency)
   * const proof = await prover.proveBytes(witnessStack[witnessStack.length - 1].witness);
   * ```
   */
  proveBytes(witness_map: any): Uint8Array;
  /**
   * Creates a new prover from a ProveKit prover artifact.
   *
   * Accepts both binary (.pkp) and JSON formats. The format is auto-detected
   * based on the file content:
   * - Binary format: zstd-compressed postcard serialization with header
   * - JSON format: standard JSON serialization
   *
   * # Arguments
   *
   * * `prover_data` - A byte slice containing the prover artifact (binary or
   *   JSON)
   *
   * # Errors
   *
   * Returns an error if the data cannot be parsed as a valid prover
   * artifact.
   */
  constructor(prover_data: Uint8Array);
  /**
   * Generates a proof from a witness map and returns it as a JavaScript
   * object.
   *
   * Similar to [`proveBytes`](Self::prove_bytes), but returns the proof as a
   * structured JavaScript object instead of JSON bytes.
   *
   * Note: The prover is consumed after this call (single-use for memory efficiency).
   *
   * # Arguments
   *
   * * `witness_map` - JavaScript Map or object mapping witness indices to
   *   hex-encoded field element strings
   *
   * # Errors
   *
   * Returns an error if the witness map cannot be parsed or proof generation
   * fails.
   */
  proveJs(witness_map: any): any;
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
  readonly prover_new: (a: number, b: number) => [number, number, number];
  readonly prover_proveBytes: (a: number, b: number) => [number, number, number, number];
  readonly prover_proveJs: (a: number, b: number) => [number, number, number];
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
