import type { Proof, VerifierScheme } from "./proof-types.js";
import type { UploadState } from "./upload-rules.js";

export const BUILT_IN_CIRCUITS = ["passkey", "webauthn"] as const;

export type BuiltInCircuitName = (typeof BUILT_IN_CIRCUITS)[number];
export type CircuitName = BuiltInCircuitName | "custom";
export type LogType = "info" | "success" | "warn" | "error";

export interface LogWriter {
  log(message: string, type?: LogType): void;
}

export interface DiagnosticsWriter extends LogWriter {
  logMemory(label: string, extras?: Record<string, unknown>): void;
}

export type BackendId = "acir" | "mavros";

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
  backend?: BackendId;
  label?: string;
  constraints?: number;
  witnesses?: number;
}

export interface BackendStatus {
  available: boolean;
  backend?: BackendId;
  label?: string;
  error?: string;
}
