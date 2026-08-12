import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright-core";
import { startRendererRssSampler } from "../../shared/browser-process-memory";
import { startServer } from "./server";

const workloads = [
  "passport_complete_age_check",
  "passport_p1",
  "webauthn_assertion",
  "oprf_taceo",
  "oprf_world_id_nullifier",
] as const;
type Workload = (typeof workloads)[number];

const workload = (process.env.MOBENCH_WORKLOAD ?? "webauthn_assertion") as Workload;
if (!workloads.includes(workload)) {
  throw new Error(`MOBENCH_WORKLOAD must be one of ${workloads.join(", ")}`);
}

const executablePath =
  process.env.CHROME_PATH ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const warmup = Number.parseInt(process.env.MOBENCH_WARMUP ?? "1", 10);
const iterations = Number.parseInt(process.env.MOBENCH_ITERATIONS ?? "5", 10);
const timingMode = process.env.MOBENCH_TIMING_MODE === "cold_local" ? "cold_local" : "warm_reuse";
const requestedThreads = Number.parseInt(process.env.MOBENCH_BB_THREADS ?? "1", 10);
if (!Number.isInteger(requestedThreads) || requestedThreads < 1 || requestedThreads > 32) {
  throw new Error("MOBENCH_BB_THREADS must be an integer from 1 to 32");
}
const server = startServer();
const profile = await mkdtemp(join(tmpdir(), "provekit-barretenberg-chrome-"));
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
  const crsResponses = new Map<
    string,
    { url: string; range: string; size_bytes: number }
  >();
  page.on("response", (response) => {
    if (!response.url().includes("crs.aztec")) return;
    const headers = response.headers();
    const size = Number.parseInt(headers["content-length"] ?? "", 10);
    if (!Number.isSafeInteger(size) || size < 0) return;
    const range = response.request().headers()["range"] ?? "";
    crsResponses.set(`${response.url()}|${range}`, {
      url: response.url(),
      range,
      size_bytes: size,
    });
  });
  page.on("console", (message) => console.error(`[browser:${message.type()}] ${message.text()}`));
  page.on("pageerror", (error) => console.error(`[browser:error] ${error.message}`));
  await page.goto(server.url.toString());
  await page.waitForFunction(() => typeof window.mobench?.run === "function", undefined, {
    timeout: 60_000,
  });
  sampler = startRendererRssSampler(profile);
  const report = await page.evaluate(
    async ({ name, warmupCount, iterationCount, timingMode, threads }) =>
      window.mobench.run({
        name: `barretenberg::${name}::e2e`,
        warmup: warmupCount,
        iterations: iterationCount,
        timing_mode: timingMode,
        threads,
      }),
    {
      name: workload,
      warmupCount: warmup,
      iterationCount: iterations,
      timingMode,
      threads: requestedThreads,
    },
  );
  const processMemory = await sampler.stop();
  sampler = undefined;
  const crsRequests = [...crsResponses.values()];
  console.log(
    JSON.stringify(
      {
        ...(report as object),
        process_memory: processMemory,
        proving_payload_transport: {
          crs_requests: crsRequests,
          crs_size_bytes: crsRequests.reduce(
            (sum, request) => sum + request.size_bytes,
            0,
          ),
        },
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

declare global {
  interface Window {
    mobench: {
      run(spec: {
        name: string;
        warmup: number;
        iterations: number;
        timing_mode?: "cold_local" | "warm_reuse";
        threads?: number;
      }): Promise<unknown>;
    };
  }
}
