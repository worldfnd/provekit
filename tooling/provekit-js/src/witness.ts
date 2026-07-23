import { decompressWitnessStack } from "@noir-lang/acvm_js";
import { Noir } from "@noir-lang/noir_js";

import { ProveKitError, ProveKitErrorCode } from "./errors.js";

const MAX_WITNESS_INDEX = 0xffff_ffff;
const BN254_MODULUS = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const DECIMAL_INDEX = /^(?:Witness\()?([0-9]+)\)?$/;
const FIELD_HEX = /^(?:0x)?([0-9a-fA-F]+)$/;

let noirRuntimeInitialization: Promise<void> | undefined;

async function ensureBrowserNoirRuntime(): Promise<void> {
  if (typeof window === "undefined") return;
  noirRuntimeInitialization ??= (async () => {
    const [acvm, abi, acvmWasm, abiWasm] = await Promise.all([
      import("@noir-lang/acvm_js"),
      import("@noir-lang/noirc_abi"),
      // @ts-expect-error Browser asset URL resolved by the consumer bundler.
      import("@noir-lang/acvm_js/web/acvm_js_bg.wasm?url"),
      // @ts-expect-error Browser asset URL resolved by the consumer bundler.
      import("@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url"),
    ]);
    const initAcvm = acvm.default as unknown as (url: string) => Promise<unknown>;
    const initAbi = abi.default as unknown as (url: string) => Promise<unknown>;
    await Promise.all([
      initAcvm(acvmWasm.default as string),
      initAbi(abiWasm.default as string),
    ]);
  })().catch((error: unknown) => {
    noirRuntimeInitialization = undefined;
    throw error;
  });
  return noirRuntimeInitialization;
}

function checkedIndex(value: unknown): number | null {
  let candidate: unknown = value;

  if (typeof candidate === "object" && candidate !== null) {
    const primitive = Reflect.get(candidate, Symbol.toPrimitive);
    if (typeof primitive === "function") {
      candidate = Reflect.apply(primitive, candidate, ["number"]);
    } else {
      const text = String(candidate);
      if (DECIMAL_INDEX.test(text)) candidate = text;
      else {
        const inner = Reflect.get(candidate, "inner");
        if (inner !== undefined) candidate = inner;
      }
    }
  }

  if (typeof candidate === "string") {
    const match = DECIMAL_INDEX.exec(candidate);
    if (!match?.[1]) return null;
    candidate = Number(match[1]);
  } else if (typeof candidate === "bigint") {
    if (candidate < 0n || candidate > BigInt(MAX_WITNESS_INDEX)) return null;
    candidate = Number(candidate);
  }

  return typeof candidate === "number" &&
    Number.isSafeInteger(candidate) &&
    candidate >= 0 &&
    candidate <= MAX_WITNESS_INDEX
    ? candidate
    : null;
}

function checkedField(value: unknown, index: number): string {
  if (typeof value !== "string") {
    throw new ProveKitError(
      ProveKitErrorCode.WITNESS_FORMAT,
      `Witness ${index} value must be a hexadecimal string`,
    );
  }
  const match = FIELD_HEX.exec(value);
  if (!match?.[1] || match[1].length > 64) {
    throw new ProveKitError(
      ProveKitErrorCode.WITNESS_FORMAT,
      `Witness ${index} is not a 1-32 byte hexadecimal field element`,
    );
  }
  const numeric = BigInt(`0x${match[1]}`);
  if (numeric >= BN254_MODULUS) {
    throw new ProveKitError(
      ProveKitErrorCode.WITNESS_FORMAT,
      `Witness ${index} is not canonical in the BN254 scalar field`,
    );
  }
  return `0x${match[1].toLowerCase()}`;
}

/** Strictly converts Noir witness keys and canonical BN254 values for WASM. */
export function convertWitnessMap(witnessMap: Map<unknown, unknown>): Record<string, string> {
  if (!(witnessMap instanceof Map) || witnessMap.size === 0) {
    throw new ProveKitError(ProveKitErrorCode.WITNESS_FORMAT, "Witness map is empty or invalid");
  }

  const converted: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [key, value] of witnessMap) {
    let index: number | null = null;
    try {
      index = checkedIndex(key);
    } catch {
      // User-defined coercion hooks are not allowed to escape this boundary.
    }
    if (index === null) {
      throw new ProveKitError(
        ProveKitErrorCode.WITNESS_FORMAT,
        "Cannot extract a canonical u32 witness index from the Noir witness key",
      );
    }
    const indexKey = String(index);
    if (Object.hasOwn(converted, indexKey)) {
      throw new ProveKitError(
        ProveKitErrorCode.WITNESS_FORMAT,
        `Duplicate witness index after normalization: ${index}`,
      );
    }
    converted[indexKey] = checkedField(value, index);
  }
  return converted;
}

export interface WitnessExecution {
  witnessMap: Map<unknown, unknown>;
  release(): void;
}

/** Executes the artifact ABI locally with Noir/ACVM 1.0.0-beta.20. */
export async function executeNoirWitness(
  circuit: unknown,
  inputs: Record<string, unknown>,
): Promise<WitnessExecution> {
  let compressed: Uint8Array | undefined;
  let witnessMap: Map<unknown, unknown> | undefined;
  try {
    await ensureBrowserNoirRuntime();
    const noir = new Noir(circuit as ConstructorParameters<typeof Noir>[0]);
    // Public input validation happens before this boundary. Noir's InputMap is
    // intentionally more specific than the SDK's ABI-agnostic object type.
    const result = await noir.execute(inputs as Parameters<Noir["execute"]>[0]);
    compressed = result.witness;
    const stack = decompressWitnessStack(compressed) as unknown;
    if (!Array.isArray(stack) || stack.length === 0) {
      throw new Error("ACVM returned an empty witness stack");
    }
    const first = stack[0] as { witness?: unknown } | undefined;
    if (!(first?.witness instanceof Map)) {
      throw new Error("ACVM witness stack does not contain a Map");
    }
    witnessMap = first.witness as Map<unknown, unknown>;
    return {
      witnessMap,
      release() {
        witnessMap?.clear();
        compressed?.fill(0);
      },
    };
  } catch (error) {
    witnessMap?.clear();
    compressed?.fill(0);
    if (error instanceof ProveKitError) throw error;
    throw new ProveKitError(
      ProveKitErrorCode.WITNESS_GENERATION,
      "Noir witness generation failed",
      { cause: error },
    );
  }
}
