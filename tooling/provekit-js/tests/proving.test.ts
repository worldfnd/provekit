import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@noir-lang/noir_js", () => ({
  Noir: class {
    async execute() {
      return { witness: new Uint8Array([1, 2, 3]) };
    }
  },
}));

vi.mock("@noir-lang/acvm_js", () => ({
  decompressWitnessStack: () => [{ witness: new Map([[{ inner: 0 }, "0x01"]]) }],
}));

import { ProveKitErrorCode } from "../src/errors.js";
import { initProveKit, resetInitializationForTests } from "../src/runtime.js";
import { artifact, fakeModule } from "./helpers.js";

beforeEach(() => resetInitializationForTests());

describe("logical prover", () => {
  it("reconstructs and frees a consumed low-level prover for every proof", async () => {
    const { module, counters } = fakeModule();
    const runtime = await initProveKit({ threads: false, wasmModule: module });
    const prover = await runtime.loadProver(artifact("prover"));
    const proof1 = await prover.prove({ secret: "1" });
    const proof2 = await prover.prove('{"secret":"2"}');
    expect(proof1.size).toBeGreaterThan(0);
    expect(proof2.size).toBeGreaterThan(0);
    expect(counters.proverConstruct).toBe(3);
    expect(counters.proverFree).toBe(3);
  });

  it("rejects non-object JSON inputs", async () => {
    const { module } = fakeModule();
    const runtime = await initProveKit({ threads: false, wasmModule: module });
    const prover = await runtime.loadProver(artifact("prover"));
    await expect(prover.prove("[]")).rejects.toMatchObject({
      code: ProveKitErrorCode.INVALID_ARGUMENT,
    });
  });
});
