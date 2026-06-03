import { Proof, type ProverScheme, type VerifierScheme } from "./proof-types.js";

interface VerityWasmProver {
  getCircuit(): Uint8Array;
  proveBytes(witnessMap: Record<string, unknown>): Uint8Array;
  free(): void;
}

interface VerityWasmVerifier {
  verifyBytes(proof: Uint8Array): void;
  free(): void;
}

interface VerityWasmModule {
  default(moduleOrPath?: unknown): Promise<unknown>;
  initPanicHook?: () => void;
  Prover: new (bytes: Uint8Array) => VerityWasmProver;
  Verifier: new (bytes: Uint8Array) => VerityWasmVerifier;
}

type WitnessKey = number | string | { inner?: unknown };

let wasmModulePromise: Promise<VerityWasmModule> | null = null;

async function loadVerityWasm(): Promise<VerityWasmModule> {
  if (!wasmModulePromise) {
    wasmModulePromise = import("verity-provekit-wasm")
      .then(async (module) => {
        const wasmModule = module as VerityWasmModule;
        await wasmModule.default();
        wasmModule.initPanicHook?.();
        return wasmModule;
      });
  }
  return wasmModulePromise;
}

function witnessIndex(key: WitnessKey): number {
  const index = typeof key === "number"
    ? key
    : typeof key === "object" && key !== null && typeof key.inner === "number"
      ? key.inner
      : Number(key);

  if (Number.isNaN(index)) {
    throw new Error(`Failed to extract witness index from key: ${String(key)}`);
  }
  return index;
}

function convertWitnessMap(witnessMap: Map<WitnessKey, unknown>): Record<string, unknown> {
  const converted: Record<string, unknown> = {};
  for (const [key, value] of witnessMap.entries()) {
    converted[witnessIndex(key)] = value;
  }
  return converted;
}

function parseCircuitJson(wasmModule: VerityWasmModule, proverBytes: Uint8Array): unknown {
  const tempProver = new wasmModule.Prover(proverBytes);
  try {
    return JSON.parse(new TextDecoder().decode(tempProver.getCircuit())) as unknown;
  } finally {
    tempProver.free();
  }
}

class VerityV1ProverScheme implements ProverScheme {
  private disposed = false;

  constructor(
    private readonly wasmModule: VerityWasmModule,
    private readonly proverBytes: Uint8Array,
    private readonly circuitJson: unknown,
  ) {}

  async prove(inputs: Record<string, unknown> | string): Promise<Proof> {
    if (this.disposed) {
      throw new Error("Verity v1 prover has been disposed");
    }

    const [{ Noir }, { decompressWitnessStack }] = await Promise.all([
      import("@provekit-v1/noir_js"),
      import("@provekit-v1/acvm_js"),
    ]);
    const parsedInputs = typeof inputs === "string" ? JSON.parse(inputs) as Record<string, unknown> : inputs;
    const noir = new Noir(this.circuitJson as never);
    const { witness: compressedWitness } = await noir.execute(parsedInputs as never);
    const witnessStack = decompressWitnessStack(compressedWitness);
    const witnessMap = witnessStack[0]?.witness;
    if (!witnessMap) {
      throw new Error("v1 circuit execution produced an empty witness stack");
    }

    const prover = new this.wasmModule.Prover(this.proverBytes);
    try {
      return Proof.fromBytes(prover.proveBytes(convertWitnessMap(witnessMap)));
    } finally {
      prover.free();
    }
  }

  async serialize(): Promise<Uint8Array> {
    return new Uint8Array(this.proverBytes);
  }

  dispose(): void {
    this.disposed = true;
  }
}

class VerityV1VerifierScheme implements VerifierScheme {
  private disposed = false;

  constructor(
    private readonly verifierBytes: Uint8Array,
    private verifier: VerityWasmVerifier | null,
  ) {}

  async verify(proof: Proof): Promise<boolean> {
    if (this.disposed || !this.verifier) {
      throw new Error("Verity v1 verifier has been disposed");
    }

    try {
      this.verifier.verifyBytes(proof.data);
      return true;
    } catch {
      return false;
    }
  }

  async serialize(): Promise<Uint8Array> {
    return new Uint8Array(this.verifierBytes);
  }

  dispose(): void {
    this.disposed = true;
    this.verifier?.free();
    this.verifier = null;
  }
}

export async function loadVerityV1Schemes(
  proverBytes: Uint8Array,
  verifierBytes: Uint8Array,
): Promise<{ prover: ProverScheme; verifier: VerifierScheme }> {
  const wasmModule = await loadVerityWasm();
  const circuitJson = parseCircuitJson(wasmModule, proverBytes);

  return {
    prover: new VerityV1ProverScheme(wasmModule, new Uint8Array(proverBytes), circuitJson),
    verifier: new VerityV1VerifierScheme(new Uint8Array(verifierBytes), new wasmModule.Verifier(verifierBytes)),
  };
}
