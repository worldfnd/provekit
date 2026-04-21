export type UploadKey = "prover" | "verifier" | "inputs";

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
  return null;
}

export interface UploadState {
  prover?: File;
  verifier?: File;
  inputs?: File;
}

export function isCustomReady(files: UploadState, wasmReady: boolean): boolean {
  return wasmReady && Boolean(files.prover && files.verifier && files.inputs);
}
