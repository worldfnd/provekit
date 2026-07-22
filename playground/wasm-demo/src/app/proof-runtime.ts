import { initProveKit, type ProveKitRuntime } from "@worldcoin/provekit";

import type { LogWriter } from "./types.js";

let runtime: ProveKitRuntime | null = null;

export async function readCircuitStatsFromPkp(proverBytes: Uint8Array): Promise<{ constraints: number; witnesses: number }> {
  runtime ??= await initProveKit({ threads: "auto" });
  const stats = runtime.inspectProver(proverBytes);
  return {
    constraints: stats.constraints ?? 0,
    witnesses: stats.witnesses ?? 0,
  };
}

export async function initializeRuntime(logSink: LogWriter): Promise<ProveKitRuntime> {
  runtime ??= await initProveKit({ threads: "auto" });
  const { mode, threads, fallbackReason } = runtime.threading;
  logSink.log(
    mode === "threaded"
      ? `Proof runtime initialized with ${threads} worker threads`
      : "Proof runtime initialized in single-threaded mode",
    "success",
  );
  if (fallbackReason) logSink.log(fallbackReason, "warn");
  return runtime;
}
