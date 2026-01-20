"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseDebugSymbols = parseDebugSymbols;
exports.extractCallStack = extractCallStack;
const pako_1 = require("pako");
const base64_decode_1 = require("./base64_decode.cjs");
function parseDebugSymbols(debugSymbols) {
    return JSON.parse((0, pako_1.inflate)((0, base64_decode_1.base64Decode)(debugSymbols), { to: 'string', raw: true })).debug_infos;
}
/**
 * Extracts the call stack from an thrown by the acvm.
 * @param error - The error to extract from.
 * @param debug - The debug metadata of the program called.
 * @param files - The files used for compilation of the program.
 * @returns The call stack, if available.
 */
function extractCallStack(error, debug, files) {
    if (!('callStack' in error) || !error.callStack) {
        return undefined;
    }
    const { callStack, brilligFunctionId } = error;
    if (!debug) {
        return callStack;
    }
    try {
        return resolveOpcodeLocations(callStack, debug, files, brilligFunctionId);
    }
    catch (_err) {
        return callStack;
    }
}
/**
 * Resolves the source code locations from an array of opcode locations
 */
function resolveOpcodeLocations(opcodeLocations, debug, files, brilligFunctionId) {
    let locations = opcodeLocations.flatMap((opcodeLocation) => getSourceCodeLocationsFromOpcodeLocation(opcodeLocation, debug, files, brilligFunctionId));
    // Adds the acir call stack if the last location is a brillig opcode
    if (locations.length > 0) {
        const decomposedOpcodeLocation = opcodeLocations[opcodeLocations.length - 1].split('.');
        if (decomposedOpcodeLocation.length === 2) {
            const acirCallstackId = debug.acir_locations[decomposedOpcodeLocation[0]];
            if (acirCallstackId !== undefined) {
                const callStack = debug.location_tree.locations[acirCallstackId];
                const acirCallstack = getCallStackFromLocationNode(callStack, debug.location_tree.locations, files);
                locations = acirCallstack.concat(locations);
            }
        }
    }
    return locations;
}
function getCallStackFromLocationNode(callStack, location_tree, files) {
    const result = [];
    while (callStack.parent !== null) {
        const { file: fileId, span } = callStack.value;
        const { path, source } = files[fileId];
        const locationText = source.substring(span.start, span.end);
        const precedingText = source.substring(0, span.start);
        const previousLines = precedingText.split('\n');
        // Lines and columns in stacks are one indexed.
        const line = previousLines.length;
        const column = previousLines[previousLines.length - 1].length + 1;
        result.push({
            filePath: path,
            line,
            column,
            locationText,
        });
        callStack = location_tree[callStack.parent];
    }
    // Reverse since we explored the child nodes first
    return result.reverse();
}
/**
 * Extracts the call stack from the location of a failing opcode and the debug metadata.
 * One opcode can point to multiple calls due to inlining.
 */
function getSourceCodeLocationsFromOpcodeLocation(opcodeLocation, debug, files, brilligFunctionId) {
    let callstack_id = debug.acir_locations[opcodeLocation];
    const brilligLocation = extractBrilligLocation(opcodeLocation);
    if (brilligFunctionId !== undefined && brilligLocation !== undefined) {
        callstack_id = debug.brillig_locations[brilligFunctionId][brilligLocation];
        if (callstack_id === undefined) {
            return [];
        }
    }
    if (callstack_id === undefined) {
        return [];
    }
    const callStack = debug.location_tree.locations[callstack_id];
    return getCallStackFromLocationNode(callStack, debug.location_tree.locations, files);
}
/**
 * Extracts a brillig location from an opcode location.
 */
function extractBrilligLocation(opcodeLocation) {
    const splitted = opcodeLocation.split('.');
    if (splitted.length === 2) {
        return splitted[1];
    }
    return undefined;
}
