import { describe, expect, it } from "vitest";

import { Proof } from "../src/proof.js";

describe("Proof.fromBytes", () => {
  it("copies a Uint8Array (independent buffer)", () => {
    const src = new Uint8Array([1, 2, 3, 4]);
    const proof = Proof.fromBytes(src);
    src[0] = 99;
    expect(Array.from(proof.bytes)).toEqual([1, 2, 3, 4]);
    expect(proof.size).toBe(4);
  });

  it("accepts an ArrayBuffer", () => {
    const buffer = new Uint8Array([5, 6, 7]).buffer;
    const proof = Proof.fromBytes(buffer);
    expect(Array.from(proof.bytes)).toEqual([5, 6, 7]);
  });

  it("accepts an ArrayBufferView with offset", () => {
    const backing = new Uint8Array([0, 0, 9, 8, 7, 0]);
    const view = new Uint8Array(backing.buffer, 2, 3);
    const proof = Proof.fromBytes(view);
    expect(Array.from(proof.bytes)).toEqual([9, 8, 7]);
  });

  it("round-trips JSON proofs", () => {
    const payload = { whir: "v1", n: 42 };
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    const proof = Proof.fromBytes(bytes);
    expect(proof.json()).toEqual(payload);
    expect(proof.text()).toEqual(JSON.stringify(payload));
  });
});
