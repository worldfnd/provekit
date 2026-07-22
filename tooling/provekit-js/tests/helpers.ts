import type {
  ProveKitWasmModule,
  WasmProverHandle,
  WasmVerifierHandle,
} from "../src/wasm-types.js";

const MAGIC = [0xdc, 0xdf, 0x4f, 0x5a, 0x6b, 0x70, 0x01, 0x00];

export function artifact(kind: "prover" | "verifier", major = 2, minor?: number): Uint8Array {
  const format = new TextEncoder().encode(kind === "prover" ? "PrvKitPr" : "PrvKitVr");
  const bytes = new Uint8Array(27);
  bytes.set(MAGIC, 0);
  bytes.set(format, 8);
  bytes[16] = major & 0xff;
  bytes[17] = major >> 8;
  const actualMinor = minor ?? (kind === "prover" ? 0 : 1);
  bytes[18] = actualMinor & 0xff;
  bytes[19] = actualMinor >> 8;
  bytes[20] = 3;
  bytes.set([0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00], 21);
  return bytes;
}

export interface FakeCounters {
  init: number;
  threadInit: number;
  proverConstruct: number;
  proverFree: number;
  verifierConstruct: number;
  verifierFree: number;
  verify: number;
}

export function fakeModule(overrides: Partial<ProveKitWasmModule> = {}): {
  module: ProveKitWasmModule;
  counters: FakeCounters;
} {
  const counters: FakeCounters = {
    init: 0,
    threadInit: 0,
    proverConstruct: 0,
    proverFree: 0,
    verifierConstruct: 0,
    verifierFree: 0,
    verify: 0,
  };

  class FakeProver implements WasmProverHandle {
    constructor(_artifact: Uint8Array) {
      counters.proverConstruct += 1;
    }
    getCircuit(): Uint8Array {
      return new TextEncoder().encode('{"abi":{},"bytecode":"AA=="}');
    }
    getNumConstraints(): number {
      return 10;
    }
    getNumWitnesses(): number {
      return 20;
    }
    proveBytes(_witness: Record<string, string>): Uint8Array {
      return new TextEncoder().encode('{"public_inputs":[],"whir_r1cs_proof":{}}');
    }
    free(): void {
      counters.proverFree += 1;
    }
  }

  class FakeVerifier implements WasmVerifierHandle {
    constructor(_artifact: Uint8Array) {
      counters.verifierConstruct += 1;
    }
    verifyBytes(proof: Uint8Array): boolean {
      counters.verify += 1;
      try {
        const parsed = JSON.parse(new TextDecoder().decode(proof)) as Record<string, unknown>;
        if (!("public_inputs" in parsed) || !("whir_r1cs_proof" in parsed)) {
          throw new Error("missing proof fields");
        }
      } catch (cause) {
        throw Object.assign(new Error("Failed to parse proof JSON", { cause }), {
          code: "PROOF_MALFORMED",
        });
      }
      return true;
    }
    free(): void {
      counters.verifierFree += 1;
    }
  }

  const module: ProveKitWasmModule = {
    async default() {
      counters.init += 1;
    },
    async initThreadPool() {
      counters.threadInit += 1;
    },
    Prover: FakeProver,
    Verifier: FakeVerifier,
    ...overrides,
  };
  return { module, counters };
}
