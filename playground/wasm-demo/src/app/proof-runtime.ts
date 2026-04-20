import { Backend, Verity } from "@atheonxyz/verity";
import initProvekitInspector, { Prover as ProvekitInspectorProver } from "provekit-inspector";

import type { LogWriter } from "./types.js";

let inspectorReady: Promise<void> | null = null;

async function ensureInspectorReady(): Promise<void> {
  inspectorReady ??= initProvekitInspector();
  await inspectorReady;
}

export async function readCircuitStatsFromPkp(proverBytes: Uint8Array): Promise<{ constraints: number; witnesses: number }> {
  await ensureInspectorReady();
  const inspector = new ProvekitInspectorProver(proverBytes);
  try {
    return {
      constraints: inspector.getNumConstraints(),
      witnesses: inspector.getNumWitnesses(),
    };
  } finally {
    inspector.free();
  }
}

export async function initializeRuntime(logSink: LogWriter, threadCountElement: HTMLElement | null): Promise<Verity> {
  const isIos = /iPhone|iPad|iPod/.test(navigator.userAgent);
  const isAndroid = /Android/.test(navigator.userAgent);
  const isMobile = isIos || isAndroid;
  const hasSharedArrayBuffer = typeof SharedArrayBuffer !== "undefined";
  const maxThreads = navigator.hardwareConcurrency || 4;

  let threadSetting: number | false = false;
  let threadLabel = 1;

  if (isIos) {
    logSink.log("📱 iOS detected - WebKit WASM threading is unreliable");
    logSink.log("Running in single-threaded mode (optimized for iOS)");
  } else if (!hasSharedArrayBuffer) {
    if (!isMobile) {
      logSink.log("SharedArrayBuffer not available, running single-threaded", "warn");
    } else {
      logSink.log("Mobile: running in single-threaded mode");
    }
  } else if (isAndroid) {
    threadSetting = Math.min(maxThreads, 4);
    threadLabel = threadSetting;
    logSink.log(`📱 Android detected, requesting ${threadSetting} worker threads...`);
  } else {
    threadSetting = maxThreads;
    threadLabel = threadSetting;
    logSink.log(`Requesting ${threadSetting} worker threads...`);
  }

  const runtime = await Verity.create(Backend.ProveKit, { threads: threadSetting });
  if (threadCountElement) {
    threadCountElement.textContent = String(threadLabel);
  }
  logSink.log("Proof runtime initialized", "success");
  return runtime;
}
