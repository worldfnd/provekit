import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { chromium } from "../../../barretenberg/node_modules/playwright-core/index.mjs";
import { startRendererRssSampler } from "../../../scripts/browser-process-memory";

const root = resolve(import.meta.dir, "dist");
const mimeTypes: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
};
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 4189,
  async fetch(request) {
    const url = new URL(request.url);
    const requested = resolve(root, `.${url.pathname === "/" ? "/index.html" : url.pathname}`);
    if (requested !== root && !requested.startsWith(`${root}${sep}`)) return new Response("not found", { status: 404 });
    const file = Bun.file(requested);
    if (!(await file.exists())) return new Response("not found", { status: 404 });
    const extension = requested.slice(requested.lastIndexOf("."));
    return new Response(file, { headers: {
      "Content-Type": mimeTypes[extension] ?? "application/octet-stream",
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Opener-Policy": "same-origin",
    }});
  },
});
const executablePath = process.env.CHROME_PATH ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const profile = await mkdtemp(join(tmpdir(), "provekit-p1-barretenberg-chrome-"));
const context = await chromium.launchPersistentContext(profile, {
  executablePath,
  headless: true,
  args: ["--enable-precise-memory-info", "--js-flags=--max-old-space-size=32768"],
});
let sampler: ReturnType<typeof startRendererRssSampler> | undefined;
const browserDiagnostics: string[] = [];
try {
  const page = context.pages()[0] ?? await context.newPage();
  page.on("console", (message) => browserDiagnostics.push(`[console:${message.type()}] ${message.text()}`));
  page.on("pageerror", (error) => browserDiagnostics.push(`[pageerror] ${error.message}`));
  await page.goto(server.url.toString());
  await page.waitForFunction(() => typeof window.passportP1?.run === "function", undefined, { timeout: 60_000 });
  sampler = startRendererRssSampler(profile);
  const warmup = Number.parseInt(process.env.MOBENCH_WARMUP ?? "1", 10);
  const iterations = Number.parseInt(process.env.MOBENCH_ITERATIONS ?? "5", 10);
  const report = await page.evaluate(
    ({ warmupCount, iterationCount }) => window.passportP1.run(warmupCount, iterationCount),
    { warmupCount: warmup, iterationCount: iterations },
  );
  const processMemory = await sampler.stop();
  sampler = undefined;
  const evidence = {
    schema_version: 1,
    profile: "P1",
    browser: { name: "Google Chrome", version: context.browser()?.version() ?? "unknown", headless: true },
    report,
    process_memory: processMemory,
  };
  await Bun.write(resolve(import.meta.dir, "../target/barretenberg-chrome-evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify(evidence, null, 2));
} catch (error) {
  const diagnostic = {
    schema_version: 1,
    profile: "P1",
    status: "error",
    error: error instanceof Error ? `${error.name}: ${error.message}\n${error.stack ?? ""}` : String(error),
    browser_diagnostics: browserDiagnostics,
  };
  await Bun.write(resolve(import.meta.dir, "../target/barretenberg-chrome-error.json"), `${JSON.stringify(diagnostic, null, 2)}\n`);
  throw error;
} finally {
  if (sampler) await sampler.stop();
  await context.close();
  server.stop(true);
  await rm(profile, { recursive: true, force: true });
}

declare global {
  interface Window { passportP1: { run(warmup: number, iterations: number): Promise<unknown> } }
}
