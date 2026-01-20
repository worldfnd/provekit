import { CompiledCircuit } from '@noir-lang/types';
import { InputMap, InputValue } from '@noir-lang/noirc_abi';
import { ForeignCallHandler } from '@noir-lang/acvm_js';
export declare class Noir {
    private circuit;
    constructor(circuit: CompiledCircuit);
    /** @ignore */
    init(): Promise<void>;
    /**
     * @description
     * Allows to execute a circuit to get its witness and return value.
     *
     * @example
     * ```typescript
     * async execute(inputs)
     * ```
     */
    execute(inputs: InputMap, foreignCallHandler?: ForeignCallHandler): Promise<{
        witness: Uint8Array;
        returnValue: InputValue;
    }>;
}
