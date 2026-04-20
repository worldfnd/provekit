import type { Proof, VerifierScheme, Verity } from "@atheonxyz/verity";

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
  runtime: Verity | null;
  lastProof: Proof | null;
  activeVerifier: VerifierScheme | null;
}

export interface CircuitMetadata {
  name?: string;
  constraints?: number;
  witnesses?: number;
}
