import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium } from "playwright-core";

const root = resolve(process.env.CIRCOM_WEB_DIST ?? resolve(import.meta.dir, "dist"));
const workload = process.env.MOBENCH_WORKLOAD ?? "webauthn";
const warmup = Number.parseInt(process.env.MOBENCH_WARMUP ?? "1", 10);
const iterations = Number.parseInt(process.env.MOBENCH_ITERATIONS ?? "5", 10);
const timingMode = process.env.MOBENCH_TIMING_MODE === "cold_local" ? "cold_local" : "warm_reuse";
const singleThread = process.env.MOBENCH_SNARKJS_SINGLE_THREAD === "1";
const requestedProverThreads = Number.parseInt(
  process.env.MOBENCH_SNARKJS_THREADS ?? (singleThread ? "1" : "0"),
  10,
);
if (!Number.isInteger(requestedProverThreads) || requestedProverThreads < 0 || requestedProverThreads > 64) {
  throw new Error("MOBENCH_SNARKJS_THREADS must be 0 (auto) or an integer from 1 to 64");
}
const timeoutMs = Number.parseInt(process.env.MOBENCH_TIMEOUT_MS ?? "900000", 10);
const chrome =
  process.env.CHROME_PATH ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const server = Bun.serve({
  port: 0,
  async fetch(request) {
    const url = new URL(request.url);
    const file = Bun.file(resolve(root, `.${url.pathname === "/" ? "/index.html" : url.pathname}`));
    if (!(await file.exists())) return new Response("not found", { status: 404 });
    return new Response(file, {
      headers: {
        "Cache-Control": "no-store",
        // Keep the browser surface consistent with the other threaded WASM
        // lanes. snarkjs Blob workers do not require SAB, but this makes the
        // execution policy observable and catches an accidentally non-isolated
        // deployment before it is used for comparison.
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
      },
    });
  },
});

interface ProcessRow {
  pid: number;
  ppid: number;
  rss_kib: number;
  command: string;
}

interface MemorySample {
  at_ms: number;
  renderer_pid: number;
  renderer_rss_kib: number;
}

async function processRows(): Promise<ProcessRow[]> {
  const child = Bun.spawn(["ps", "-axo", "pid=,ppid=,rss=,command="], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    child.exited,
  ]);
  if (exitCode !== 0) return [];
  return stdout
    .split("\n")
    .flatMap((line) => {
      const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/);
      if (!match) return [];
      return [{
        pid: Number.parseInt(match[1], 10),
        ppid: Number.parseInt(match[2], 10),
        rss_kib: Number.parseInt(match[3], 10),
        command: match[4],
      }];
    });
}

async function rendererSnapshot(profile: string): Promise<MemorySample | null> {
  const rows = await processRows();
  const root = rows.find(
    (row) =>
      row.command.includes(profile) &&
      row.command.includes("Google Chrome") &&
      !row.command.includes("--type="),
  );
  if (!root) return null;
  const descendants = new Set([root.pid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const row of rows) {
      if (descendants.has(row.ppid) && !descendants.has(row.pid)) {
        descendants.add(row.pid);
        changed = true;
      }
    }
  }
  const renderer = rows
    .filter((row) => descendants.has(row.pid) && row.command.includes("--type=renderer"))
    .sort((left, right) => right.rss_kib - left.rss_kib)[0];
  return renderer
    ? {
        at_ms: Date.now(),
        renderer_pid: renderer.pid,
        renderer_rss_kib: renderer.rss_kib,
      }
    : null;
}

const profile = await mkdtemp(join(tmpdir(), "provekit-circom-chrome-"));
try {
  const context = await chromium.launchPersistentContext(profile, {
    executablePath: chrome,
    headless: true,
    args: ["--js-flags=--max-old-space-size=32768"],
  });
  try {
    const page = context.pages()[0] ?? (await context.newPage());
    if (!singleThread && requestedProverThreads > 0) {
      // SnarkJS 0.7.6 sizes its worker pool from navigator.hardwareConcurrency
      // and exposes no public worker-count option. Pin the browser lane to the
      // requested count so a large zkey cannot spawn one full copy per host
      // core and exhaust the renderer. This remains a genuine multithreaded
      // run; the effective value is recorded in the report.
      await page.addInitScript((threads) => {
        Object.defineProperty(navigator, "hardwareConcurrency", {
          configurable: true,
          value: threads,
        });
      }, requestedProverThreads);
    }
    page.on("console", (message) => {
      if (message.text().startsWith("MOBENCH_PROGRESS ")) {
        console.error(message.text());
      }
    });
    await page.goto(`http://127.0.0.1:${server.port}/`);
    let sampling = true;
    const memorySamples: MemorySample[] = [];
    const sampler = (async () => {
      while (sampling) {
        const sample = await rendererSnapshot(profile);
        if (sample) memorySamples.push(sample);
        await Bun.sleep(100);
      }
    })();
    const benchmark = page.evaluate(
      async ({ iterations, singleThread, warmup, workload, timingMode, proverThreads }) =>
        window.mobenchCircom.run({
          workload: workload as never,
          warmup,
          iterations,
          single_thread: singleThread,
          prover_threads: proverThreads > 0 ? proverThreads : undefined,
          timing_mode: timingMode,
        }),
      {
        workload,
        warmup,
        iterations,
        singleThread,
        timingMode,
        proverThreads: requestedProverThreads,
      },
    );
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timeoutHandle = setTimeout(
        () => reject(new Error(`benchmark exceeded ${timeoutMs} ms`)),
        timeoutMs,
      );
    });
    try {
      const result = await Promise.race([benchmark, timeout]);
      sampling = false;
      await sampler;
      const peak = memorySamples.sort(
        (left, right) => right.renderer_rss_kib - left.renderer_rss_kib,
      )[0];
      const observedHardwareConcurrency = await page
        .evaluate(() => navigator.hardwareConcurrency || 1)
        .catch(() => null);
      console.log(JSON.stringify({
        ...(result as Record<string, unknown>),
        process_memory: {
          metric: "peak_chrome_renderer_rss",
          peak_rss_kib: peak?.renderer_rss_kib ?? null,
          peak_renderer_pid: peak?.renderer_pid ?? null,
          polling_interval_ms: 100,
          sample_count: memorySamples.length,
          chrome_profile: profile,
        },
      }));
    } catch (error) {
      sampling = false;
      await sampler;
      const progress = await page.evaluate(() => window.mobenchCircom.progress).catch(() => []);
      const peak = memorySamples.sort(
        (left, right) => right.renderer_rss_kib - left.renderer_rss_kib,
      )[0];
      const observedHardwareConcurrency = await page
        .evaluate(() => navigator.hardwareConcurrency || 1)
        .catch(() => null);
      console.log(JSON.stringify({
        schema_version: 1,
        stack: "circom_groth16",
        backend: "snarkjs_0.7.6_browser_wasm",
        runtime: "browser-wasm",
        workload,
        status: error instanceof Error && error.message.includes("exceeded")
          ? "timed_out"
          : "runtime_failed",
        failure_class: error instanceof Error && error.message.includes("exceeded")
          ? "attempt_timeout"
          : "browser_runtime",
        failure_message: error instanceof Error ? error.message : String(error),
        warmup_attempts_requested: warmup,
        measured_attempts_requested: iterations,
        single_thread: singleThread,
        witness_backend: "circom_runtime_wasm_single",
        witness_threads: 1,
        prover_threads_requested: requestedProverThreads > 0
          ? requestedProverThreads
          : null,
        prover_threads_effective: singleThread
          ? 1
          : requestedProverThreads > 0
            ? Math.min(requestedProverThreads, observedHardwareConcurrency ?? 1, 64)
            : null,
        worker_available: true,
        hardware_concurrency: observedHardwareConcurrency,
        cross_origin_isolated: await page.evaluate(() => self.crossOriginIsolated).catch(() => null),
        progress,
        process_memory: {
          metric: "peak_chrome_renderer_rss",
          peak_rss_kib: peak?.renderer_rss_kib ?? null,
          peak_renderer_pid: peak?.renderer_pid ?? null,
          polling_interval_ms: 100,
          sample_count: memorySamples.length,
          chrome_profile: profile,
        },
        samples: [],
      }));
    } finally {
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
    }
  } finally {
    await context.close();
  }
} finally {
  server.stop(true);
  await rm(profile, { recursive: true, force: true });
}
