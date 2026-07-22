import { describe, expect, it } from "vitest";

import { ProveKitErrorCode, mapRuntimeError } from "../src/errors.js";

describe("structured low-level errors", () => {
  it.each([
    ["ARTIFACT_INCOMPATIBLE_VERSION", ProveKitErrorCode.ARTIFACT_VERSION],
    ["ARTIFACT_DECOMPRESSED_TOO_LARGE", ProveKitErrorCode.ARTIFACT_TOO_LARGE],
    ["ARTIFACT_INVALID_MAGIC", ProveKitErrorCode.ARTIFACT_FORMAT],
    ["WITNESS_INVALID", ProveKitErrorCode.WITNESS_FORMAT],
    ["PROOF_MALFORMED", ProveKitErrorCode.MALFORMED_PROOF],
  ])("maps %s to %s", (code, expected) => {
    const error = Object.assign(new Error("low-level detail"), { code });
    expect(mapRuntimeError(error, ProveKitErrorCode.PROVING_FAILED, "operation")).toMatchObject({
      code: expected,
    });
  });
});
