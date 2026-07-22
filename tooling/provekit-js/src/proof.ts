import type { ArtifactLimits } from "./artifacts.js";
import { DEFAULT_ARTIFACT_LIMITS } from "./artifacts.js";
import { ProveKitError, ProveKitErrorCode } from "./errors.js";

const PROOF_DATA = new WeakMap<Proof, Uint8Array>();

/** Immutable wrapper around ProveKit's serialized proof bytes. */
export class Proof {
  private constructor(data: Uint8Array) {
    PROOF_DATA.set(this, new Uint8Array(data));
  }

  static fromBytes(
    data: Uint8Array,
    maxBytes: number = DEFAULT_ARTIFACT_LIMITS.maxProofBytes,
  ): Proof {
    if (!(data instanceof Uint8Array) || data.byteLength === 0) {
      throw new ProveKitError(ProveKitErrorCode.MALFORMED_PROOF, "Proof bytes cannot be empty");
    }
    if (data.byteLength > maxBytes) {
      throw new ProveKitError(
        ProveKitErrorCode.ARTIFACT_TOO_LARGE,
        `Proof is ${data.byteLength} bytes; maximum is ${maxBytes}`,
      );
    }
    return new Proof(data);
  }

  get size(): number {
    return proofData(this).byteLength;
  }

  get bytes(): Uint8Array {
    return new Uint8Array(proofData(this));
  }

  hexPreview(maxBytes = 32): string {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
      throw new ProveKitError(
        ProveKitErrorCode.INVALID_ARGUMENT,
        "maxBytes must be a non-negative safe integer",
      );
    }
    const data = proofData(this);
    const prefix = Array.from(data.subarray(0, maxBytes), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    return data.byteLength > maxBytes ? `${prefix}...` : prefix;
  }
}

function proofData(proof: Proof): Uint8Array {
  const data = PROOF_DATA.get(proof);
  if (!data) {
    throw new ProveKitError(ProveKitErrorCode.MALFORMED_PROOF, "Invalid Proof instance");
  }
  return data;
}

/** @internal Returns immutable-to-consumers bytes for the WASM verification boundary. */
export function proofBytesForVerification(proof: Proof, limits: ArtifactLimits): Uint8Array {
  const data = proofData(proof);
  if (data.byteLength > limits.maxProofBytes) {
    throw new ProveKitError(
      ProveKitErrorCode.ARTIFACT_TOO_LARGE,
      `Proof is ${data.byteLength} bytes; maximum is ${limits.maxProofBytes}`,
    );
  }
  return data;
}
