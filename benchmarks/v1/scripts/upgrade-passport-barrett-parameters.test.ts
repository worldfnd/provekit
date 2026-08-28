import { describe, expect, test } from "bun:test";

import {
  barrettParameter,
  bytesToBigInt,
  upgradePassportBarrettParameters,
} from "./upgrade-passport-barrett-parameters";

describe("Passport Barrett parameter migration", () => {
  test("uses the six overflow bits required by noir-bignum v0.10.0", () => {
    const modulus = [0x80, 0x01];
    const parameter = barrettParameter(modulus);
    const expected = (1n << (2n * 16n + 6n)) / bytesToBigInt(modulus);
    expect(bytesToBigInt(parameter)).toBe(expected);
    expect(parameter).toHaveLength(modulus.length + 1);
  });

  test("upgrades both Passport RSA parameters idempotently", () => {
    const source = [
      "dsc_pubkey = [128,1]",
      "dsc_barrett_mu = [0,0,0]",
      "csc_pubkey = [128,3,5]",
      "csc_barrett_mu = [0,0,0,0]",
      "",
    ].join("\n");
    const upgraded = upgradePassportBarrettParameters(source);
    expect(upgraded).not.toBe(source);
    expect(upgradePassportBarrettParameters(upgraded)).toBe(upgraded);
  });
});
