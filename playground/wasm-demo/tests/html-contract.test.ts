import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const currentDir = dirname(fileURLToPath(import.meta.url));
const indexHtml = readFileSync(join(currentDir, "..", "index.html"), "utf8");

describe("index.html runtime contract", () => {
  it("removes the old inline control script and onclick handlers", () => {
    expect(indexHtml).not.toContain('onclick="runDemo()"');
    expect(indexHtml).not.toContain('onclick="verifyProof()"');
    expect(indexHtml).not.toContain("MutationObserver");
    expect(indexHtml).not.toContain("window.activeCircuit");
    expect(indexHtml).not.toContain("window.runDemo");
    expect(indexHtml).toContain('src="./dist/src/main.js"');
  });

  it("retains the browser import map required by the static-serve TypeScript path", () => {
    expect(indexHtml).toContain('"verity-provekit-wasm"');
    expect(indexHtml).toContain('"@provekit-v1/noir_js"');
    expect(indexHtml).toContain('"@provekit-v1/acvm_js"');
    expect(indexHtml).toContain('"provekit-inspector"');
    expect(indexHtml).toContain('"provekit-sdk"');
  });

  it("exposes passkey and WebAuthn as built-in circuit options", () => {
    expect(indexHtml).toContain('data-circuit="passkey"');
    expect(indexHtml).toContain('data-circuit="webauthn"');
    expect(indexHtml).toContain("Passkey");
    expect(indexHtml).toContain("WebAuthn");
  });

  it("exposes the backend comparison panel", () => {
    expect(indexHtml).toContain('id="compareBtn"');
    expect(indexHtml).toContain('id="comparisonBody"');
    expect(indexHtml).toContain("Mavros main");
    expect(indexHtml).toContain("ProveKit v1 ACIR (Verity WASM)");
  });
});
