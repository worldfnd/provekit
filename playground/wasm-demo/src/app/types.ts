import type { Proof, ProveKitRuntime, Verifier } from "provekit-sdk";

export type CircuitName = "sha256" | "poseidon" | "custom";
export type LogType = "info" | "success" | "warn" | "error";

export interface LogWriter {
  log(message: string, type?: LogType): void;
}

export interface DiagnosticsWriter extends LogWriter {
  logMemory(label: string, extras?: Record<string, unknown>): void;
}

export interface CustomFiles {
  prover?: File;
  verifier?: File;
  inputs?: File;
}

export interface AppState {
  activeCircuit: CircuitName;
  customFiles: CustomFiles;
  wasmReady: boolean;
  runtime: ProveKitRuntime | null;
  lastProof: Proof | null;
  activeVerifier: Verifier | null;
}

export interface CircuitMetadata {
  name?: string;
  constraints?: number;
  witnesses?: number;
}
