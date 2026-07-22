import { describe, expect, it, vi } from "vitest";

import { ArtifactLoader } from "../src/app/artifact-loader.js";

function fakeFile(name: string, size: number) {
  return {
    name,
    size,
    arrayBuffer: vi.fn(async () => new ArrayBuffer(size)),
    text: vi.fn(async () => "{}"),
  } as unknown as File;
}

function createLoader() {
  const logs = { log: vi.fn(), logMemory: vi.fn() };
  return new ArtifactLoader(logs, vi.fn(async () => ({ constraints: 1, witnesses: 1 })), {
    maxProverBytes: 10,
    maxVerifierBytes: 10,
    maxProofBytes: 10,
  });
}

describe("ArtifactLoader resource limits", () => {
  it("rejects oversized custom artifacts before reading their bytes", async () => {
    const prover = fakeFile("prover.pkp", 11);
    const verifier = fakeFile("verifier.pkv", 1);

    await expect(createLoader().loadArtifacts("custom", { prover, verifier })).rejects.toThrow(
      "Prover artifact is 11 bytes; maximum is 10 bytes",
    );
    expect(prover.arrayBuffer).not.toHaveBeenCalled();
    expect(verifier.arrayBuffer).not.toHaveBeenCalled();
  });

  it("rejects oversized custom inputs before reading text", async () => {
    const inputs = fakeFile("inputs.json", 4 * 1024 * 1024 + 1);

    await expect(createLoader().loadInputs("custom", { inputs })).rejects.toThrow(
      "Input file is 4194305 bytes; maximum is 4194304 bytes",
    );
    expect(inputs.text).not.toHaveBeenCalled();
  });
});
