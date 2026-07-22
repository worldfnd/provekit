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
    expect(indexHtml).toContain('"@worldcoin/provekit"');
    expect(indexHtml).toContain('"@noir-lang/noir_js"');
  });
});
