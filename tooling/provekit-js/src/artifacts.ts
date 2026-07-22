import { ProveKitError, ProveKitErrorCode } from "./errors.js";

const HEADER_SIZE = 21;
const MAGIC = new Uint8Array([0xdc, 0xdf, 0x4f, 0x5a, 0x6b, 0x70, 0x01, 0x00]);
const TEXT_DECODER = new TextDecoder();

export type ArtifactKind = "prover" | "verifier";

export interface ArtifactLimits {
  maxProverBytes: number;
  maxVerifierBytes: number;
  maxProofBytes: number;
}

export const DEFAULT_ARTIFACT_LIMITS: Readonly<ArtifactLimits> = Object.freeze({
  maxProverBytes: 64 * 1024 * 1024,
  maxVerifierBytes: 64 * 1024 * 1024,
  maxProofBytes: 16 * 1024 * 1024,
});

const EXPECTED = {
  prover: { format: "PrvKitPr", major: 2, minor: 0 },
  verifier: { format: "PrvKitVr", major: 2, minor: 1 },
} as const;

export interface ArtifactMetadata {
  kind: ArtifactKind;
  major: number;
  minor: number;
  hashConfig: number;
  byteLength: number;
}

function equalBytes(actual: Uint8Array, expected: Uint8Array): boolean {
  return expected.every((value, index) => actual[index] === value);
}

function readU16Le(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8);
}

export function preflightArtifact(
  data: Uint8Array,
  kind: ArtifactKind,
  limits: ArtifactLimits = DEFAULT_ARTIFACT_LIMITS,
): ArtifactMetadata {
  const maxBytes = kind === "prover" ? limits.maxProverBytes : limits.maxVerifierBytes;
  if (data.byteLength > maxBytes) {
    throw new ProveKitError(
      ProveKitErrorCode.ARTIFACT_TOO_LARGE,
      `${kind} artifact is ${data.byteLength} bytes; maximum is ${maxBytes}`,
    );
  }
  if (data.byteLength < HEADER_SIZE) {
    throw new ProveKitError(
      ProveKitErrorCode.ARTIFACT_FORMAT,
      `${kind} artifact is too short for the ${HEADER_SIZE}-byte ProveKit header`,
    );
  }
  if (!equalBytes(data.subarray(0, MAGIC.length), MAGIC)) {
    throw new ProveKitError(
      ProveKitErrorCode.ARTIFACT_FORMAT,
      `${kind} artifact does not have ProveKit binary magic; JSON and legacy artifacts are unsupported`,
    );
  }

  const expected = EXPECTED[kind];
  const format = TEXT_DECODER.decode(data.subarray(8, 16));
  if (format !== expected.format) {
    throw new ProveKitError(
      ProveKitErrorCode.ARTIFACT_FORMAT,
      `Expected ${expected.format} ${kind} artifact, received ${JSON.stringify(format)}`,
    );
  }

  const major = readU16Le(data, 16);
  const minor = readU16Le(data, 18);
  if (major !== expected.major || minor < expected.minor) {
    throw new ProveKitError(
      ProveKitErrorCode.ARTIFACT_VERSION,
      `Unsupported ${kind} artifact version ${major}.${minor}; expected ${expected.major}.${expected.minor} or newer compatible minor`,
    );
  }

  return {
    kind,
    major,
    minor,
    hashConfig: data[20] ?? 0xff,
    byteLength: data.byteLength,
  };
}

export function normalizeLimits(overrides?: Partial<ArtifactLimits>): ArtifactLimits {
  const limits = { ...DEFAULT_ARTIFACT_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new ProveKitError(
        ProveKitErrorCode.INVALID_ARGUMENT,
        `${name} must be a positive safe integer`,
      );
    }
  }
  return limits;
}
