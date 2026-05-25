import { describe, expect, it, vi } from "vitest";

import { createProveKit } from "../src/sdk.js";
import type { ProveKitWasmBindings } from "../src/types.js";

interface FakeProverInit {
  kind: string;
  proveBytes?: Uint8Array;
}

function makeBindings(prover: FakeProverInit, verifier?: { rejects?: boolean }): ProveKitWasmBindings {
  const freeProver = vi.fn();
  const freeVerifier = vi.fn();

  class FakeProver {
    free = freeProver;
    getProverKind(): string {
      return prover.kind;
    }
    getCircuit(): Uint8Array {
      return new TextEncoder().encode("{}");
    }
    proveBytes(): Uint8Array {
      return prover.proveBytes ?? new Uint8Array([1, 2, 3]);
    }
  }

  class FakeVerifier {
    free = freeVerifier;
    verifyBytes(_proof: Uint8Array): void {
      if (verifier?.rejects) {
        throw new Error("invalid proof");
      }
    }
  }

  return {
    Prover: FakeProver as unknown as ProveKitWasmBindings["Prover"],
    Verifier: FakeVerifier as unknown as ProveKitWasmBindings["Verifier"],
    initPanicHook: vi.fn(),
  };
}

describe("createProveKit", () => {
  it("calls init, panic hook, and skips thread pool when threads=false", async () => {
    const init = vi.fn().mockResolvedValue(undefined);
    const bindings = makeBindings({ kind: "noir" });
    await createProveKit({ bindings, init, threads: false });
    expect(init).toHaveBeenCalledOnce();
    expect(bindings.initPanicHook).toHaveBeenCalledOnce();
  });
});

describe("ProveKit.loadArtifacts", () => {
  it("errors when a Noir prover has no witnessProvider", async () => {
    const bindings = makeBindings({ kind: "noir" });
    const provekit = await createProveKit({ bindings, threads: false });
    await expect(
      provekit.loadArtifacts({ prover: new Uint8Array([0]), verifier: new Uint8Array([0]) }),
    ).rejects.toThrow(/witnessProvider/);
  });

  it("errors when a Mavros prover has no provingModules", async () => {
    const bindings = makeBindings({ kind: "mavros" });
    const provekit = await createProveKit({ bindings, threads: false });
    await expect(
      provekit.loadArtifacts({ prover: new Uint8Array([0]), verifier: new Uint8Array([0]) }),
    ).rejects.toThrow(/provingModules/);
  });

  it("rejects unknown prover kinds", async () => {
    const bindings = makeBindings({ kind: "groth16" });
    const provekit = await createProveKit({ bindings, threads: false });
    await expect(
      provekit.loadArtifacts({ prover: new Uint8Array([0]), verifier: new Uint8Array([0]) }),
    ).rejects.toThrow(/Unsupported ProveKit prover kind/);
  });

  it("skips the verifier when skipVerifier is set", async () => {
    const bindings = makeBindings({ kind: "noir" });
    const provekit = await createProveKit({ bindings, threads: false });
    const scheme = await provekit.loadArtifacts({
      prover: new Uint8Array([0]),
      skipVerifier: true,
      witnessProvider: { generateWitness: async () => ({}) },
    });
    await expect(scheme.verify(new Uint8Array([1]))).rejects.toThrow(/No verifier/);
    scheme.dispose();
  });
});

describe("ProveKitScheme.dispose", () => {
  it("is idempotent and safe to call repeatedly", async () => {
    const bindings = makeBindings({ kind: "noir" });
    const provekit = await createProveKit({ bindings, threads: false });
    const scheme = await provekit.loadArtifacts({
      prover: new Uint8Array([0]),
      verifier: new Uint8Array([0]),
      witnessProvider: { generateWitness: async () => ({}) },
    });
    scheme.dispose();
    scheme.dispose();
    scheme.dispose();
  });
});

describe("ProveKitScheme.tryVerify vs verify", () => {
  it("verify throws on rejection; tryVerify returns false", async () => {
    const bindings = makeBindings({ kind: "noir" }, { rejects: true });
    const provekit = await createProveKit({ bindings, threads: false });
    const scheme = await provekit.loadArtifacts({
      prover: new Uint8Array([0]),
      verifier: new Uint8Array([0]),
      witnessProvider: { generateWitness: async () => ({}) },
    });
    await expect(scheme.verify(new Uint8Array([1]))).rejects.toThrow(/invalid proof/);
    await expect(scheme.tryVerify(new Uint8Array([1]))).resolves.toBe(false);
    scheme.dispose();
  });

  it("tryVerify still throws when no verifier is loaded", async () => {
    const bindings = makeBindings({ kind: "noir" });
    const provekit = await createProveKit({ bindings, threads: false });
    const scheme = await provekit.loadArtifacts({
      prover: new Uint8Array([0]),
      skipVerifier: true,
      witnessProvider: { generateWitness: async () => ({}) },
    });
    await expect(scheme.tryVerify(new Uint8Array([1]))).rejects.toThrow(/No verifier/);
    scheme.dispose();
  });
});
