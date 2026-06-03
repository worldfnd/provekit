import type { Proof, VerifierScheme } from "./proof-types.js";
import type { UploadState } from "./upload-rules.js";

export const BUILT_IN_CIRCUITS = ["sha256", "poseidon", "passkey"] as const;

export type BuiltInCircuitName = (typeof BUILT_IN_CIRCUITS)[number];
export type CircuitName = BuiltInCircuitName | "custom";
export type LogType = "info" | "success" | "warn" | "error";

export interface LogWriter {
  log(message: string, type?: LogType): void;
}

export interface DiagnosticsWriter extends LogWriter {
  logMemory(label: string, extras?: Record<string, unknown>): void;
}

export type CustomFiles = UploadState;

export interface AppState {
  activeCircuit: CircuitName;
  customFiles: CustomFiles;
  wasmReady: boolean;
  lastProof: Proof | null;
  activeVerifier: VerifierScheme | null;
}

export interface CircuitMetadata {
  name?: string;
  constraints?: number;
  witnesses?: number;
}
