"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateWitness = generateWitness;
const noirc_abi_1 = require("@noir-lang/noirc_abi");
const base64_decode_js_1 = require("./base64_decode.cjs");
const acvm_js_1 = require("@noir-lang/acvm_js");
const debug_js_1 = require("./debug.cjs");
const defaultForeignCallHandler = async (name, args) => {
    if (name == 'print') {
        // By default we do not print anything for `print` foreign calls due to a need for formatting,
        // however we provide an empty response in order to not halt execution.
        //
        // If a user needs to print values then they should provide a custom foreign call handler.
        return [];
    }
    throw Error(`Unexpected oracle during execution: ${name}(${args.join(', ')})`);
};
function enrichExecutionError(artifact, originalError) {
    const enrichedError = originalError;
    if (originalError.rawAssertionPayload) {
        try {
            // Decode the payload
            const decodedPayload = (0, noirc_abi_1.abiDecodeError)(artifact.abi, originalError.rawAssertionPayload);
            if (typeof decodedPayload === 'string') {
                // If it's a string, just add it to the error message
                enrichedError.message = `Circuit execution failed: ${decodedPayload}`;
            }
            else {
                // If not, attach the payload to the original error
                enrichedError.decodedAssertionPayload = decodedPayload;
            }
        }
        catch (_errorDecoding) {
            // Ignore errors decoding the payload
        }
    }
    try {
        // Decode the callstack
        const callStack = (0, debug_js_1.extractCallStack)(originalError, (0, debug_js_1.parseDebugSymbols)(artifact.debug_symbols)[originalError.acirFunctionId], artifact.file_map);
        enrichedError.noirCallStack = callStack?.map((errorLocation) => {
            if (typeof errorLocation === 'string') {
                return `at opcode ${errorLocation}`;
            }
            else {
                return `at ${errorLocation.locationText} (${errorLocation.filePath}:${errorLocation.line}:${errorLocation.column})`;
            }
        });
    }
    catch (_errorResolving) {
        // Ignore errors resolving the callstack
    }
    return enrichedError;
}
// Generates the witnesses needed to feed into the chosen proving system
async function generateWitness(compiledProgram, inputs, foreignCallHandler = defaultForeignCallHandler) {
    // Throws on ABI encoding error
    const witnessMap = (0, noirc_abi_1.abiEncode)(compiledProgram.abi, inputs);
    // Execute the circuit to generate the rest of the witnesses and serialize
    // them into a Uint8Array.
    try {
        const solvedWitness = await (0, acvm_js_1.executeProgram)((0, base64_decode_js_1.base64Decode)(compiledProgram.bytecode), witnessMap, foreignCallHandler);
        return solvedWitness;
    }
    catch (err) {
        // Typescript types catched errors as unknown or any, so we need to narrow its type to check if it has raw assertion payload.
        if (typeof err === 'object' && err !== null && 'rawAssertionPayload' in err) {
            throw enrichExecutionError(compiledProgram, err);
        }
        throw new Error(`Circuit execution failed: ${err}`);
    }
}
