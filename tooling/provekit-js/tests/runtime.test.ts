import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ProveKitErrorCode } from "../src/errors.js";
import { initProveKit, resetInitializationForTests } from "../src/runtime.js";
import { artifact, fakeModule } from "./helpers.js";

beforeEach(() => resetInitializationForTests());
afterEach(() => resetInitializationForTests());

describe("runtime initialization", () => {
  it("is race-safe and initializes a shared module once", async () => {
    const { module, counters } = fakeModule();
    const source = () => Promise.resolve(module);
    const [first, second] = await Promise.all([
      initProveKit({ threads: false, wasmModule: source }),
      initProveKit({ threads: false, wasmModule: source }),
    ]);
    expect(first).toBe(second);
    expect(counters.init).toBe(1);
  });

  it("clears a failed initialization so a later attempt can retry", async () => {
    const failing = fakeModule({
      default: vi.fn().mockRejectedValue(new Error("load failed")),
    }).module;
    await expect(initProveKit({ threads: false, wasmModule: failing })).rejects.toMatchObject({
      code: ProveKitErrorCode.INITIALIZATION_FAILED,
    });

    const succeeding = fakeModule().module;
    await expect(initProveKit({ threads: false, wasmModule: succeeding })).resolves.toBeDefined();
  });

  it("auto mode explains its single-thread fallback without browser isolation", async () => {
    const { module, counters } = fakeModule();
    const runtime = await initProveKit({ threads: "auto", wasmModule: module });
    expect(runtime.threading).toMatchObject({ mode: "single", threads: 1 });
    expect(runtime.threading.fallbackReason).toContain("outside a browser");
    expect(counters.threadInit).toBe(0);
  });

  it("rejects explicit threads when browser prerequisites are unavailable", async () => {
    const { module } = fakeModule();
    await expect(initProveKit({ threads: 2, wasmModule: module })).rejects.toMatchObject({
      code: ProveKitErrorCode.THREADS_UNAVAILABLE,
    });
  });

  it("initializes a requested pool in an isolated browser", async () => {
    vi.stubGlobal("window", {});
    vi.stubGlobal("crossOriginIsolated", true);
    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 Chrome/140",
      hardwareConcurrency: 8,
      platform: "Linux",
      maxTouchPoints: 0,
    });
    const { module, counters } = fakeModule();
    const runtime = await initProveKit({ threads: 3, wasmModule: module });
    expect(runtime.threading).toEqual({ mode: "threaded", threads: 3 });
    expect(counters.threadInit).toBe(1);
  });

  it("caps automatic worker selection to limit browser memory pressure", async () => {
    vi.stubGlobal("window", {});
    vi.stubGlobal("crossOriginIsolated", true);
    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 Chrome/140",
      hardwareConcurrency: 64,
      platform: "Linux",
      maxTouchPoints: 0,
    });
    const { module } = fakeModule();
    const runtime = await initProveKit({ threads: "auto", wasmModule: module });
    expect(runtime.threading).toEqual({ mode: "threaded", threads: 8 });
  });

  it("rejects conflicting global options", async () => {
    const { module } = fakeModule();
    await initProveKit({ threads: false, wasmModule: module });
    await expect(initProveKit({ threads: "auto", wasmModule: module })).rejects.toMatchObject({
      code: ProveKitErrorCode.INITIALIZATION_CONFLICT,
    });
  });
});

describe("artifact handles", () => {
  it("frees temporary and retained handles and guards disposed resources", async () => {
    const { module, counters } = fakeModule();
    const runtime = await initProveKit({ threads: false, wasmModule: module });
    const prover = await runtime.loadProver(artifact("prover"));
    const verifier = await runtime.loadVerifier(artifact("verifier"));

    expect(counters.proverFree).toBe(1);
    expect(await verifier.verify((await import("../src/proof.js")).Proof.fromBytes(
      new TextEncoder().encode('{"public_inputs":[],"whir_r1cs_proof":{}}'),
    ))).toBe(true);
    verifier.dispose();
    verifier.dispose();
    prover.dispose();
    prover.dispose();
    expect(counters.verifierFree).toBe(1);
    expect(() => prover.serialize()).toThrowError(expect.objectContaining({ code: ProveKitErrorCode.DISPOSED }));
    await expect(verifier.verify((await import("../src/proof.js")).Proof.fromBytes(
      new TextEncoder().encode("{}"),
    ))).rejects.toMatchObject({ code: ProveKitErrorCode.DISPOSED });
  });

  it("inspects a prover without leaking its low-level handle", async () => {
    const { module, counters } = fakeModule();
    const runtime = await initProveKit({ threads: false, wasmModule: module });
    expect(runtime.inspectProver(artifact("prover"))).toEqual({ constraints: 10, witnesses: 20 });
    expect(counters.proverFree).toBe(1);
  });

  it("returns false only when the low-level verifier reports mathematical rejection", async () => {
    const { module } = fakeModule();
    module.Verifier = class {
      verifyBytes(): boolean {
        return false;
      }
      free(): void {}
    };
    const runtime = await initProveKit({ threads: false, wasmModule: module });
    const verifier = await runtime.loadVerifier(artifact("verifier"));
    const { Proof } = await import("../src/proof.js");
    const proof = Proof.fromBytes(new TextEncoder().encode('{"public_inputs":[],"whir_r1cs_proof":{}}'));
    await expect(verifier.verify(proof)).resolves.toBe(false);
  });

  it("maps malformed proof errors from the WASM boundary", async () => {
    const { module, counters } = fakeModule();
    const runtime = await initProveKit({ threads: false, wasmModule: module });
    const verifier = await runtime.loadVerifier(artifact("verifier"));
    const { Proof } = await import("../src/proof.js");
    await expect(verifier.verify(Proof.fromBytes(new TextEncoder().encode("not-json")))).rejects.toMatchObject({
      code: ProveKitErrorCode.MALFORMED_PROOF,
    });
    expect(counters.verify).toBe(1);
  });
});
