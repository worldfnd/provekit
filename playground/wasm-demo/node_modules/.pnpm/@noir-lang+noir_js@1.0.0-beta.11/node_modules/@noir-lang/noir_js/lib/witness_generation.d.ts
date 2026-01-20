import { InputMap } from '@noir-lang/noirc_abi';
import { WitnessStack, ForeignCallHandler, ExecutionError } from '@noir-lang/acvm_js';
import { CompiledCircuit } from '@noir-lang/types';
export type ErrorWithPayload = ExecutionError & {
    decodedAssertionPayload?: any;
    noirCallStack?: string[];
};
export declare function generateWitness(compiledProgram: CompiledCircuit, inputs: InputMap, foreignCallHandler?: ForeignCallHandler): Promise<WitnessStack>;
