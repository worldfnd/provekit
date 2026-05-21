import { describe, expect, it } from "vitest";

import { createMavrosRunner } from "../src/app/mavros-runtime";

describe("mavros runtime", () => {
  it("rejects invalid uploaded Mavros WASM artifacts before execution", async () => {
    const invalidModule = new Uint8Array([0, 1, 2, 3]);

    await expect(createMavrosRunner(invalidModule, invalidModule)).rejects.toThrow();
  });
});
