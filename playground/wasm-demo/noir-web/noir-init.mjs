/**
 * noir_js browser initialization wrapper
 * 
 * This module handles loading and initializing the Noir WASM modules
 * for browser usage. It uses the web builds of acvm_js and noirc_abi.
 */

// Import web builds (resolved via import map)
import initACVM, * as acvm from '@noir-lang/acvm_js';
import initNoirC, * as noirc_abi from '@noir-lang/noirc_abi';

let initialized = false;

/**
 * Decode base64 string to Uint8Array (browser implementation)
 */
function base64Decode(input) {
  return Uint8Array.from(atob(input), (c) => c.charCodeAt(0));
}

// Simple Noir class implementation for browser
// Based on the official noir_js implementation
export class Noir {
  constructor(circuit) {
    this.circuit = circuit;
  }

  async execute(inputs, foreignCallHandler) {
    if (!initialized) {
      throw new Error('Call initNoir() before executing');
    }
    
    // Default foreign call handler
    const defaultHandler = async (name, args) => {
      if (name === 'print') {
        return [];
      }
      throw new Error(`Unexpected oracle during execution: ${name}(${args.join(', ')})`);
    };
    
    const handler = foreignCallHandler || defaultHandler;
    
    // Encode inputs using noirc_abi
    const witnessMap = noirc_abi.abiEncode(this.circuit.abi, inputs);
    
    // Decode bytecode from base64 and execute
    const decodedBytecode = base64Decode(this.circuit.bytecode);
    const witnessStack = await acvm.executeProgram(decodedBytecode, witnessMap, handler);
    
    // Compress the witness stack
    const witness = acvm.compressWitnessStack(witnessStack);
    
    return { witness };
  }
}

/**
 * Initialize the Noir WASM modules.
 * Must be called before using Noir or decompressWitness.
 */
export async function initNoir() {
  if (initialized) return;
  
  // Initialize ACVM and NoirC WASM modules in parallel
  await Promise.all([
    initACVM(),
    initNoirC()
  ]);
  
  initialized = true;
  console.log('Noir WASM modules initialized');
}

/**
 * Decompress a witness from compressed format.
 * Note: This returns a witness stack, use [0].witness for the main witness.
 */
export function decompressWitness(compressed) {
  if (!initialized) {
    throw new Error('Call initNoir() before using decompressWitness');
  }
  return acvm.decompressWitnessStack(compressed);
}
