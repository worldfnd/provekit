/* tslint:disable */
/* eslint-disable */
/**
 * Performs a bitwise AND operation between `lhs` and `rhs`
 */
export function and(lhs: string, rhs: string): string;
/**
 * Performs a bitwise XOR operation between `lhs` and `rhs`
 */
export function xor(lhs: string, rhs: string): string;
/**
 * Sha256 compression function
 */
export function sha256_compression(inputs: Uint32Array, state: Uint32Array): Uint32Array;
/**
 * Calculates the Blake2s256 hash of the input bytes
 */
export function blake2s256(inputs: Uint8Array): Uint8Array;
/**
 * Verifies a ECDSA signature over the secp256k1 curve.
 */
export function ecdsa_secp256k1_verify(hashed_msg: Uint8Array, public_key_x_bytes: Uint8Array, public_key_y_bytes: Uint8Array, signature: Uint8Array): boolean;
/**
 * Verifies a ECDSA signature over the secp256r1 curve.
 */
export function ecdsa_secp256r1_verify(hashed_msg: Uint8Array, public_key_x_bytes: Uint8Array, public_key_y_bytes: Uint8Array, signature: Uint8Array): boolean;
/**
 * Returns the `BuildInfo` object containing information about how the installed package was built.
 * @returns {BuildInfo} - Information on how the installed package was built.
 */
export function buildInfo(): BuildInfo;
/**
 * Compresses a `WitnessMap` into the binary format outputted by Nargo.
 *
 * @param {WitnessMap} witness_map - A witness map.
 * @returns {Uint8Array} A compressed witness map
 */
export function compressWitness(witness_map: WitnessMap): Uint8Array;
/**
 * Decompresses a compressed witness as outputted by Nargo into a `WitnessMap`.
 * This should be used to only fetch the witness map for the main function.
 *
 * @param {Uint8Array} compressed_witness - A compressed witness.
 * @returns {WitnessMap} The decompressed witness map.
 */
export function decompressWitness(compressed_witness: Uint8Array): WitnessMap;
/**
 * Compresses a `WitnessStack` into the binary format outputted by Nargo.
 *
 * @param {WitnessStack} witness_stack - A witness stack.
 * @returns {Uint8Array} A compressed witness stack
 */
export function compressWitnessStack(witness_stack: WitnessStack): Uint8Array;
/**
 * Decompresses a compressed witness stack as outputted by Nargo into a `WitnessStack`.
 *
 * @param {Uint8Array} compressed_witness - A compressed witness.
 * @returns {WitnessStack} The decompressed witness stack.
 */
export function decompressWitnessStack(compressed_witness: Uint8Array): WitnessStack;
/**
 * Executes an ACIR circuit to generate the solved witness from the initial witness.
 *
 * @param {Uint8Array} circuit - A serialized representation of an ACIR circuit
 * @param {WitnessMap} initial_witness - The initial witness map defining all of the inputs to `circuit`..
 * @param {ForeignCallHandler} foreign_call_handler - A callback to process any foreign calls from the circuit.
 * @returns {WitnessMap} The solved witness calculated by executing the circuit on the provided inputs.
 */
export function executeCircuit(program: Uint8Array, initial_witness: WitnessMap, foreign_call_handler: ForeignCallHandler): Promise<WitnessMap>;
/**
 * Executes an ACIR circuit to generate the solved witness from the initial witness.
 * This method also extracts the public return values from the solved witness into its own return witness.
 *
 * @param {Uint8Array} circuit - A serialized representation of an ACIR circuit
 * @param {WitnessMap} initial_witness - The initial witness map defining all of the inputs to `circuit`..
 * @param {ForeignCallHandler} foreign_call_handler - A callback to process any foreign calls from the circuit.
 * @returns {SolvedAndReturnWitness} The solved witness calculated by executing the circuit on the provided inputs, as well as the return witness indices as specified by the circuit.
 */
export function executeCircuitWithReturnWitness(program: Uint8Array, initial_witness: WitnessMap, foreign_call_handler: ForeignCallHandler): Promise<SolvedAndReturnWitness>;
/**
 * Executes an ACIR circuit to generate the solved witness from the initial witness.
 *
 * @param {Uint8Array} program - A serialized representation of an ACIR program
 * @param {WitnessMap} initial_witness - The initial witness map defining all of the inputs to `program`.
 * @param {ForeignCallHandler} foreign_call_handler - A callback to process any foreign calls from the program.
 * @returns {WitnessStack} The solved witness calculated by executing the program on the provided inputs.
 */
export function executeProgram(program: Uint8Array, initial_witness: WitnessMap, foreign_call_handler: ForeignCallHandler): Promise<WitnessStack>;
/**
 * Extracts a `WitnessMap` containing the witness indices corresponding to the circuit's return values.
 *
 * @param {Uint8Array} circuit - A serialized representation of an ACIR circuit
 * @param {WitnessMap} witness_map - The completed witness map after executing the circuit.
 * @returns {WitnessMap} A witness map containing the circuit's return values.
 */
export function getReturnWitness(program: Uint8Array, witness_map: WitnessMap): WitnessMap;
/**
 * Extracts a `WitnessMap` containing the witness indices corresponding to the circuit's public parameters.
 *
 * @param {Uint8Array} circuit - A serialized representation of an ACIR circuit
 * @param {WitnessMap} witness_map - The completed witness map after executing the circuit.
 * @returns {WitnessMap} A witness map containing the circuit's public parameters.
 */
export function getPublicParametersWitness(program: Uint8Array, solved_witness: WitnessMap): WitnessMap;
/**
 * Extracts a `WitnessMap` containing the witness indices corresponding to the circuit's public inputs.
 *
 * @param {Uint8Array} circuit - A serialized representation of an ACIR circuit
 * @param {WitnessMap} witness_map - The completed witness map after executing the circuit.
 * @returns {WitnessMap} A witness map containing the circuit's public inputs.
 */
export function getPublicWitness(program: Uint8Array, solved_witness: WitnessMap): WitnessMap;
/**
 * Sets the package's logging level.
 *
 * @param {LogLevel} level - The maximum level of logging to be emitted.
 */
export function initLogLevel(filter: string): void;

export type StackItem = {
    index: number;
    witness: WitnessMap;
}

export type WitnessStack = Array<StackItem>;



/**
* @typedef {Object} BuildInfo - Information about how the installed package was built
* @property {string} gitHash - The hash of the git commit from which the package was built. 
* @property {string} version - The version of the package at the built git commit.
* @property {boolean} dirty - Whether the package contained uncommitted changes when built.
 */
export type BuildInfo = {
  gitHash: string;
  version: string;
  dirty: string;
}



export type ForeignCallInput = string[]
export type ForeignCallOutput = string | string[]

/**
* A callback which performs an foreign call and returns the response.
* @callback ForeignCallHandler
* @param {string} name - The identifier for the type of foreign call being performed.
* @param {string[][]} inputs - An array of hex encoded inputs to the foreign call.
* @returns {Promise<string[]>} outputs - An array of hex encoded outputs containing the results of the foreign call.
*/
export type ForeignCallHandler = (name: string, inputs: ForeignCallInput[]) => Promise<ForeignCallOutput[]>;



// Map from witness index to hex string value of witness.
export type WitnessMap = Map<number, string>;

/**
 * An execution result containing two witnesses.
 * 1. The full solved witness of the execution.
 * 2. The return witness which contains the given public return values within the full witness.
 */
export type SolvedAndReturnWitness = {
    solvedWitness: WitnessMap;
    returnWitness: WitnessMap;
}



export type RawAssertionPayload = {
    selector: string;
    data: string[];
};

export type ExecutionError = Error & {
    callStack?: string[];
    rawAssertionPayload?: RawAssertionPayload;
    acirFunctionId?: number;
    brilligFunctionId?: number;
};



export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly and: (a: any, b: any) => any;
  readonly xor: (a: any, b: any) => any;
  readonly sha256_compression: (a: number, b: number, c: number, d: number) => [number, number];
  readonly blake2s256: (a: number, b: number) => [number, number];
  readonly ecdsa_secp256k1_verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
  readonly ecdsa_secp256r1_verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
  readonly buildInfo: () => any;
  readonly compressWitness: (a: any) => [number, number, number, number];
  readonly decompressWitness: (a: number, b: number) => [number, number, number];
  readonly compressWitnessStack: (a: any) => [number, number, number, number];
  readonly decompressWitnessStack: (a: number, b: number) => [number, number, number];
  readonly executeCircuit: (a: number, b: number, c: any, d: any) => any;
  readonly executeCircuitWithReturnWitness: (a: number, b: number, c: any, d: any) => any;
  readonly executeProgram: (a: number, b: number, c: any, d: any) => any;
  readonly getReturnWitness: (a: number, b: number, c: any) => [number, number, number];
  readonly getPublicParametersWitness: (a: number, b: number, c: any) => [number, number, number];
  readonly getPublicWitness: (a: number, b: number, c: any) => [number, number, number];
  readonly initLogLevel: (a: number, b: number) => [number, number];
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_6: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly closure645_externref_shim: (a: number, b: number, c: any) => void;
  readonly closure1317_externref_shim: (a: number, b: number, c: any, d: number, e: any) => void;
  readonly closure1321_externref_shim: (a: number, b: number, c: any, d: any) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
