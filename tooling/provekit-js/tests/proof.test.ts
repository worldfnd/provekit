import { describe, expect, it } from "vitest";

import { ProveKitErrorCode } from "../src/errors.js";
import { Proof } from "../src/proof.js";

describe("Proof", () => {
  it("defensively copies input and output bytes", () => {
    const input = new Uint8Array([1, 2, 3]);
    const proof = Proof.fromBytes(input);
    input[0] = 9;
    const output = proof.bytes;
    output[1] = 9;
    expect(proof.bytes).toEqual(new Uint8Array([1, 2, 3]));
    expect(proof.hexPreview(2)).toBe("0102...");
  });

  it("rejects empty and oversized proofs", () => {
    expect(() => Proof.fromBytes(new Uint8Array())).toThrowError(
      expect.objectContaining({ code: ProveKitErrorCode.MALFORMED_PROOF }),
    );
    expect(() => Proof.fromBytes(new Uint8Array([1, 2]), 1)).toThrowError(
      expect.objectContaining({ code: ProveKitErrorCode.ARTIFACT_TOO_LARGE }),
    );
  });
});
