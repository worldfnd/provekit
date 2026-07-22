/** Stable error codes exposed by the browser SDK. */
export enum ProveKitErrorCode {
  INVALID_ARGUMENT = "INVALID_ARGUMENT",
  INITIALIZATION_FAILED = "INITIALIZATION_FAILED",
  INITIALIZATION_CONFLICT = "INITIALIZATION_CONFLICT",
  WASM_UNAVAILABLE = "WASM_UNAVAILABLE",
  THREADS_UNAVAILABLE = "THREADS_UNAVAILABLE",
  ARTIFACT_TOO_LARGE = "ARTIFACT_TOO_LARGE",
  ARTIFACT_FORMAT = "ARTIFACT_FORMAT",
  ARTIFACT_VERSION = "ARTIFACT_VERSION",
  WITNESS_GENERATION = "WITNESS_GENERATION",
  WITNESS_FORMAT = "WITNESS_FORMAT",
  PROVING_FAILED = "PROVING_FAILED",
  MALFORMED_PROOF = "MALFORMED_PROOF",
  OUT_OF_MEMORY = "OUT_OF_MEMORY",
  DISPOSED = "DISPOSED",
}

/** Typed failure returned by all SDK-owned validation and runtime boundaries. */
export class ProveKitError extends Error {
  readonly code: ProveKitErrorCode;

  constructor(code: ProveKitErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ProveKitError";
    this.code = code;
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function mapRuntimeError(
  error: unknown,
  fallbackCode: ProveKitErrorCode,
  operation: string,
): ProveKitError {
  if (error instanceof ProveKitError) return error;

  const detail = errorMessage(error);
  const lowLevelCode = (() => {
    if ((typeof error !== "object" && typeof error !== "function") || error === null) return undefined;
    try {
      const code = Reflect.get(error, "code");
      return typeof code === "string" ? code : undefined;
    } catch {
      return undefined;
    }
  })();
  if (lowLevelCode === "ARTIFACT_INCOMPATIBLE_VERSION") {
    return new ProveKitError(ProveKitErrorCode.ARTIFACT_VERSION, `${operation}: ${detail}`, { cause: error });
  }
  if (lowLevelCode === "ARTIFACT_TOO_LARGE" || lowLevelCode === "ARTIFACT_DECOMPRESSED_TOO_LARGE") {
    return new ProveKitError(ProveKitErrorCode.ARTIFACT_TOO_LARGE, `${operation}: ${detail}`, { cause: error });
  }
  if (lowLevelCode?.startsWith("ARTIFACT_")) {
    return new ProveKitError(ProveKitErrorCode.ARTIFACT_FORMAT, `${operation}: ${detail}`, { cause: error });
  }
  if (lowLevelCode === "WITNESS_INVALID") {
    return new ProveKitError(ProveKitErrorCode.WITNESS_FORMAT, `${operation}: ${detail}`, { cause: error });
  }
  if (lowLevelCode === "PROOF_MALFORMED") {
    return new ProveKitError(ProveKitErrorCode.MALFORMED_PROOF, `${operation}: ${detail}`, { cause: error });
  }
  const lower = detail.toLowerCase();
  if (lower.includes("out of memory") || lower.includes("memory access out of bounds")) {
    return new ProveKitError(ProveKitErrorCode.OUT_OF_MEMORY, `${operation}: ${detail}`, {
      cause: error,
    });
  }
  if (lower.includes("failed to parse proof") || lower.includes("deserialize proof")) {
    return new ProveKitError(ProveKitErrorCode.MALFORMED_PROOF, `${operation}: ${detail}`, {
      cause: error,
    });
  }
  return new ProveKitError(fallbackCode, `${operation}: ${detail}`, { cause: error });
}
