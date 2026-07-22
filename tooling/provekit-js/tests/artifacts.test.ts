import { describe, expect, it } from "vitest";

import { DEFAULT_ARTIFACT_LIMITS, preflightArtifact } from "../src/artifacts.js";
import { ProveKitErrorCode } from "../src/errors.js";
import { artifact } from "./helpers.js";

describe("artifact preflight", () => {
  it("uses browser-oriented default budgets", () => {
    expect(DEFAULT_ARTIFACT_LIMITS).toEqual({
      maxProverBytes: 64 * 1024 * 1024,
      maxVerifierBytes: 64 * 1024 * 1024,
      maxProofBytes: 16 * 1024 * 1024,
    });
  });

  it("accepts current binary PKP and PKV headers", () => {
    expect(preflightArtifact(artifact("prover"), "prover")).toMatchObject({ major: 2, minor: 0 });
    expect(preflightArtifact(artifact("verifier"), "verifier")).toMatchObject({ major: 2, minor: 1 });
  });

  it("rejects legacy artifact versions with a typed error", () => {
    expect(() => preflightArtifact(artifact("prover", 1, 1), "prover")).toThrowError(
      expect.objectContaining({ code: ProveKitErrorCode.ARTIFACT_VERSION }),
    );
  });

  it("rejects JSON and wrong-kind artifacts before WASM", () => {
    expect(() => preflightArtifact(new TextEncoder().encode("{}"), "prover")).toThrowError(
      expect.objectContaining({ code: ProveKitErrorCode.ARTIFACT_FORMAT }),
    );
    expect(() => preflightArtifact(artifact("verifier"), "prover")).toThrowError(
      expect.objectContaining({ code: ProveKitErrorCode.ARTIFACT_FORMAT }),
    );
  });

  it("enforces compressed artifact size limits", () => {
    expect(() => preflightArtifact(artifact("prover"), "prover", {
      maxProverBytes: 10,
      maxVerifierBytes: 10,
      maxProofBytes: 10,
    })).toThrowError(expect.objectContaining({ code: ProveKitErrorCode.ARTIFACT_TOO_LARGE }));
  });
});
