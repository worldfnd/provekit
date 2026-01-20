import { DebugFileMap, DebugInfo, OpcodeLocation } from '@noir-lang/types';
import { ExecutionError } from '@noir-lang/acvm_js';
/**
 * A stack of calls, resolved or not
 */
type CallStack = SourceCodeLocation[] | OpcodeLocation[];
/**
 * A resolved pointer to a failing section of the noir source code.
 */
interface SourceCodeLocation {
    /**
     * The path to the source file.
     */
    filePath: string;
    /**
     * The line number of the location.
     */
    line: number;
    /**
     * The column number of the location.
     */
    column: number;
    /**
     * The source code text of the location.
     */
    locationText: string;
}
export declare function parseDebugSymbols(debugSymbols: string): DebugInfo[];
/**
 * Extracts the call stack from an thrown by the acvm.
 * @param error - The error to extract from.
 * @param debug - The debug metadata of the program called.
 * @param files - The files used for compilation of the program.
 * @returns The call stack, if available.
 */
export declare function extractCallStack(error: ExecutionError, debug: DebugInfo, files: DebugFileMap): CallStack | undefined;
export {};
