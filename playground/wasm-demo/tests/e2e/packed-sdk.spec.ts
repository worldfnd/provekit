import { expect, test } from "playwright/test";

interface AcceptanceResult {
  mode: string;
  threads: number;
  initializationMs: number;
  firstProofMs: number;
  secondProofMs: number;
  verificationMs: number;
  proofBytes: number;
  firstValid: boolean;
  secondValid: boolean;
  tamperedValid: boolean;
}

for (const threads of [false, "auto"] as const) {
  test(`packed SDK proves and verifies locally with threads=${String(threads)}`, async ({ page }) => {
    let sensitivePhase = false;
    const sensitiveRequests: Array<{
      url: string;
      method: string;
      resourceType: string;
      postData: string | null;
      headers: Record<string, string>;
    }> = [];
    const webSockets: string[] = [];
    await page.exposeFunction("beginSensitivePhase", () => {
      sensitivePhase = true;
    });
    page.on("request", (request) => {
      if (sensitivePhase) {
        sensitiveRequests.push({
          url: request.url(),
          method: request.method(),
          resourceType: request.resourceType(),
          postData: request.postData(),
          headers: request.headers(),
        });
      }
    });
    page.on("websocket", (socket) => webSockets.push(socket.url()));

    await page.goto("/e2e.html");
    const result = await page.evaluate(async (threadSetting): Promise<AcceptanceResult> => {
      const sdk = await import("provekit-sdk");
      const started = performance.now();
      const runtime = await sdk.initProveKit({ threads: threadSetting });
      const initializationMs = performance.now() - started;
      const [pkp, pkv, inputs] = await Promise.all([
        fetch("/artifacts/sha256/prover.pkp").then(async (response) => new Uint8Array(await response.arrayBuffer())),
        fetch("/artifacts/sha256/verifier.pkv").then(async (response) => new Uint8Array(await response.arrayBuffer())),
        fetch("/artifacts/sha256/inputs.json").then(async (response) => response.json()),
      ]);
      const prover = await runtime.loadProver(pkp);
      const verifier = await runtime.loadVerifier(pkv);
      try {
        await (globalThis as typeof globalThis & {
          beginSensitivePhase: () => Promise<void>;
        }).beginSensitivePhase();
        const firstStarted = performance.now();
        const first = await prover.prove(inputs);
        const firstProofMs = performance.now() - firstStarted;
        const secondStarted = performance.now();
        const second = await prover.prove(inputs);
        const secondProofMs = performance.now() - secondStarted;
        const verifyStarted = performance.now();
        const firstValid = await verifier.verify(first);
        const secondValid = await verifier.verify(second);
        const verificationMs = performance.now() - verifyStarted;

        const decoded = JSON.parse(new TextDecoder().decode(first.bytes)) as { public_inputs?: unknown[] };
        if (!decoded.public_inputs?.length) throw new Error("fixture has no public inputs to tamper");
        const publicInput = decoded.public_inputs[0];
        if (typeof publicInput !== "string" || publicInput.length === 0) {
          throw new Error("fixture public input is not a non-empty string");
        }
        decoded.public_inputs[0] = `${publicInput[0] === "0" ? "1" : "0"}${publicInput.slice(1)}`;
        const tampered = sdk.Proof.fromBytes(new TextEncoder().encode(JSON.stringify(decoded)));
        const tamperedValid = await verifier.verify(tampered);
        return {
          mode: runtime.threading.mode,
          threads: runtime.threading.threads,
          initializationMs,
          firstProofMs,
          secondProofMs,
          verificationMs,
          proofBytes: first.size,
          firstValid,
          secondValid,
          tamperedValid,
        };
      } finally {
        prover.dispose();
        verifier.dispose();
      }
    }, threads);

    console.log(`ACCEPTANCE ${JSON.stringify({ requestedThreads: threads, ...result })}`);
    expect(result.firstValid).toBe(true);
    expect(result.secondValid).toBe(true);
    expect(result.tamperedValid).toBe(false);
    expect(result.proofBytes).toBeGreaterThan(0);
    const expectedOrigin = new URL(page.url()).origin;
    const allowedLazyWasmPaths = new Set([
      "/node_modules/@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm",
      "/node_modules/@noir-lang/acvm_js/web/acvm_js_bg.wasm",
    ]);
    const browserControlledHeaders = new Set([
      "accept-language",
      "referer",
      "sec-ch-ua",
      "sec-ch-ua-mobile",
      "sec-ch-ua-platform",
      "user-agent",
    ]);
    expect(sensitiveRequests).toHaveLength(2);
    for (const request of sensitiveRequests) {
      const url = new URL(request.url);
      expect(url.origin).toBe(expectedOrigin);
      expect(url.search).toBe("");
      expect(allowedLazyWasmPaths.has(url.pathname)).toBe(true);
      expect(request).toMatchObject({ method: "GET", resourceType: "fetch", postData: null });
      expect(Object.keys(request.headers).every((name) => browserControlledHeaders.has(name))).toBe(true);
      expect(request.headers.referer).toBe(page.url());
      expect(request.headers["accept-language"]).toBe("en-US");
    }
    expect(new Set(sensitiveRequests.map((request) => new URL(request.url).pathname))).toEqual(
      allowedLazyWasmPaths,
    );
    expect(webSockets).toEqual([]);
    expect(result.mode).toBe(threads === false ? "single" : "threaded");
  });
}
