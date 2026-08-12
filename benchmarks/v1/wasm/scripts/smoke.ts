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
  const timingMode = process.env.MOBENCH_TIMING_MODE ?? "warm_reuse";
  const wasmThreads = process.env.MOBENCH_WASM_THREADS ?? "single";
  if (
    wasmThreads !== "single" &&
    wasmThreads !== "auto" &&
    (!/^[0-9]+$/.test(wasmThreads) ||
      Number.parseInt(wasmThreads, 10) < 2 ||
      Number.parseInt(wasmThreads, 10) > 32)
  ) {
    throw new Error(
      "MOBENCH_WASM_THREADS must be `single`, `auto`, or an integer from 2 to 32",
    );
  }
  await page.goto(
    `${server.url}?autorun=1&workload=${encodeURIComponent(workload)}&warmup=${encodeURIComponent(warmup)}&iterations=${encodeURIComponent(iterations)}&timing_mode=${encodeURIComponent(timingMode)}&threads=${encodeURIComponent(wasmThreads)}`,
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
  if (wasmThreads !== "single") {
    const environment = (
      state.result as {
        environment?: { wasm_threads?: boolean; wasm_thread_mode?: string };
      }
    ).environment;
    if (environment?.wasm_threads !== true || environment.wasm_thread_mode !== "rayon_threaded") {
      throw new Error(
        `requested threaded ProveKit WASM but runtime reported ${JSON.stringify(environment)}`,
      );
    }
  }
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
