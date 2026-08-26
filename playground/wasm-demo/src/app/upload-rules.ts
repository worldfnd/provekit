export type UploadKey = "prover" | "verifier" | "inputs" | "programWasm" | "witgenWasm" | "adWasm";

const INPUT_FILE_NAME = "inputs.json";

export function classifyUpload(fileName: string): UploadKey | null {
  const normalized = fileName.toLowerCase();

  if (normalized.endsWith(".pkp")) {
    return "prover";
  }
  if (normalized.endsWith(".pkv")) {
    return "verifier";
  }
  if (normalized === INPUT_FILE_NAME || normalized.endsWith(".toml")) {
    return "inputs";
  }
  if (normalized === "program.wasm" || normalized.endsWith(".program.wasm")) {
    return "programWasm";
  }
  if (normalized === "witgen.wasm" || normalized.endsWith(".witgen.wasm")) {
    return "witgenWasm";
  }
  if (normalized === "ad.wasm" || normalized.endsWith(".ad.wasm")) {
    return "adWasm";
  }
  return null;
}

export interface UploadState {
  prover?: File;
  verifier?: File;
  inputs?: File;
  programWasm?: File;
  witgenWasm?: File;
  adWasm?: File;
}

export function isCustomReady(files: UploadState, wasmReady: boolean): boolean {
  return wasmReady && Boolean(files.prover && files.verifier && files.inputs);
}
