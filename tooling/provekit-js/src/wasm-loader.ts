import { ProveKitError, ProveKitErrorCode } from "./errors.js";
import type { ProveKitWasmModule, WasmModuleSource, WasmVariant } from "./wasm-types.js";

function isModule(value: unknown): value is ProveKitWasmModule {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as Partial<ProveKitWasmModule>;
  return typeof candidate.default === "function" &&
    typeof candidate.Prover === "function" &&
    typeof candidate.Verifier === "function";
}

export async function resolveWasmModule(
  source: WasmModuleSource | undefined,
  variant: WasmVariant,
): Promise<ProveKitWasmModule> {
  let loaded: unknown;
  if (typeof source === "function") loaded = await source();
  else if (source) loaded = await source;
  else {
    const glueUrl = new URL(`./wasm/${variant}/provekit_wasm.js`, import.meta.url);
    loaded = await import(/* @vite-ignore */ glueUrl.href);
  }

  if (!isModule(loaded)) {
    throw new ProveKitError(
      ProveKitErrorCode.WASM_UNAVAILABLE,
      "The ProveKit WASM module does not expose init, Prover, and Verifier",
    );
  }
  return loaded;
}
