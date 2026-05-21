declare module "provekit-inspector" {
  export default function initProvekitInspector(): Promise<void>;
  export function initPanicHook(): void;
  export function initThreadPool(numThreads: number): Promise<void>;

  export class Prover {
    constructor(bytes: Uint8Array);
    proveBytes(witnessMap: Record<string, unknown>): Uint8Array;
    proveJs(witnessMap: Record<string, unknown>): unknown;
    proveMavrosBytes(inputs: Record<string, unknown>, runner: unknown): Uint8Array;
    proveMavrosJs(inputs: Record<string, unknown>, runner: unknown): unknown;
    getProverKind(): string;
    getCircuit(): Uint8Array;
    getNumConstraints(): number;
    getNumWitnesses(): number;
    free(): void;
  }

  export class Verifier {
    constructor(bytes: Uint8Array);
    verifyBytes(proof: Uint8Array): void;
    verifyJs(proof: unknown): void;
    free(): void;
  }
}
