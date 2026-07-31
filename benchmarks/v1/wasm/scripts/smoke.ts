import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright-core";
import { startRendererRssSampler } from "../../shared/browser-process-memory";
import { startServer } from "./server";

const server = startServer();
const executablePath =
  process.env.CHROME_PATH ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const profile = await mkdtemp(join(tmpdir(), "provekit-wasm-chrome-"));
const context = await chromium.launchPersistentContext(profile, {
  executablePath,
  headless: true,
  args: [
    "--enable-precise-memory-info",
    "--js-flags=--max-old-space-size=32768",
  ],
});

let sampler: ReturnType<typeof startRendererRssSampler> | undefined;
try {
  const page = context.pages()[0] ?? (await context.newPage());
  const workload = process.env.MOBENCH_WORKLOAD ?? "webauthn_assertion";
  const warmup = process.env.MOBENCH_WARMUP ?? "1";
  const iterations = process.env.MOBENCH_ITERATIONS ?? "5";
  await page.goto(
    `${server.url}?autorun=1&workload=${encodeURIComponent(workload)}&warmup=${encodeURIComponent(warmup)}&iterations=${encodeURIComponent(iterations)}`,
  );
  sampler = startRendererRssSampler(profile);
  await page.waitForFunction(
    () => ["complete", "error"].includes(window.__MOBENCH_STATE__?.status),
    undefined,
    { timeout: 10 * 60 * 1000 },
  );
  const processMemory = await sampler.stop();
  sampler = undefined;
  const state = await page.evaluate(() => window.__MOBENCH_STATE__);
  if (state.status !== "complete") throw new Error(state.error ?? "browser benchmark failed");
  console.log(
    JSON.stringify(
      {
        ...(state.result as object),
        process_memory: processMemory,
        browser: {
          name: "Google Chrome",
          version: context.browser()?.version() ?? "unknown",
          executable_path: executablePath,
          headless: true,
        },
      },
      null,
      2,
    ),
  );
} finally {
  if (sampler) await sampler.stop();
  await context.close();
  server.stop(true);
  await rm(profile, { recursive: true, force: true });
}
