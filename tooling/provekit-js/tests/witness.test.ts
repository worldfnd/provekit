import { describe, expect, it } from "vitest";

import { ProveKitErrorCode } from "../src/errors.js";
import { convertWitnessMap } from "../src/witness.js";

describe("strict witness conversion", () => {
  it("supports numeric, string, bigint, symbolic, and guarded inner keys", () => {
    const symbolic = { [Symbol.toPrimitive]: () => 3 };
    const witness = new Map<unknown, unknown>([
      [0, "0x01"],
      ["1", "02"],
      [2n, "0x03"],
      [symbolic, "04"],
      [{ inner: 4 }, "0x05"],
    ]);
    expect(convertWitnessMap(witness)).toEqual({
      0: "0x01",
      1: "0x02",
      2: "0x03",
      3: "0x04",
      4: "0x05",
    });
  });

  it.each([-1, 1.5, 2 ** 32, "1.0", {}, true])("rejects non-canonical index %s", (key) => {
    expect(() => convertWitnessMap(new Map([[key, "0x01"]]))).toThrowError(
      expect.objectContaining({ code: ProveKitErrorCode.WITNESS_FORMAT }),
    );
  });

  it("rejects duplicate normalized indices", () => {
    expect(() => convertWitnessMap(new Map<unknown, unknown>([[1, "0x01"], ["1", "0x02"]]))).toThrowError(
      expect.objectContaining({ code: ProveKitErrorCode.WITNESS_FORMAT }),
    );
  });

  it("rejects values at the BN254 modulus rather than reducing them", () => {
    expect(() => convertWitnessMap(new Map([[0, "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"]]))).toThrowError(
      expect.objectContaining({ code: ProveKitErrorCode.WITNESS_FORMAT }),
    );
  });
});
