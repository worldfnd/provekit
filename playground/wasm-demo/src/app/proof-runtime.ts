import initProvekitInspector, {
  initThreadPool,
  initPanicHook,
  Prover as ProvekitInspectorProver,
} from "provekit-inspector";

import type { LogWriter } from "./types.js";

let inspectorReady: Promise<void> | null = null;

async function ensureInspectorReady(): Promise<void> {
  if (!inspectorReady) {
    inspectorReady = initProvekitInspector().catch((error) => {
      // Clear the cache so the next caller retries instead of re-throwing a
      // stuck rejection forever.
      inspectorReady = null;
      throw error;
    });
  }
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

let runtimeReady: Promise<void> | null = null;

export async function initializeRuntime(logSink: LogWriter): Promise<void> {
  if (runtimeReady) {
    await runtimeReady;
    return;
  }

  runtimeReady = initializeLocalRuntime(logSink).catch((error) => {
    runtimeReady = null;
    throw error;
  });
  await runtimeReady;
}

async function initializeLocalRuntime(logSink: LogWriter): Promise<void> {
  await ensureInspectorReady();
  initPanicHook();

  const isIos = /iPhone|iPad|iPod/.test(navigator.userAgent);
  const isAndroid = /Android/.test(navigator.userAgent);
  const isMobile = isIos || isAndroid;
  const hasSharedArrayBuffer = typeof SharedArrayBuffer !== "undefined";
  const maxThreads = navigator.hardwareConcurrency || 4;

  let threadSetting: number | false = false;

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
    logSink.log(`📱 Android detected, requesting ${threadSetting} worker threads...`);
  } else {
    threadSetting = maxThreads;
    logSink.log(`Requesting ${threadSetting} worker threads...`);
  }

  if (threadSetting !== false) {
    await initThreadPool(threadSetting);
  }
  logSink.log("Proof runtime initialized", "success");
}
