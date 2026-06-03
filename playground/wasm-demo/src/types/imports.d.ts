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

declare module "verity-provekit-wasm" {
  export default function initVerityProvekitWasm(moduleOrPath?: unknown): Promise<unknown>;
  export function initPanicHook(): void;

  export class Prover {
    constructor(bytes: Uint8Array);
    getCircuit(): Uint8Array;
    proveBytes(witnessMap: Record<string, unknown>): Uint8Array;
    free(): void;
  }

  export class Verifier {
    constructor(bytes: Uint8Array);
    verifyBytes(proof: Uint8Array): void;
    free(): void;
  }
}

declare module "@provekit-v1/noir_js" {
  export class Noir {
    constructor(circuit: never);
    execute(inputs: never): Promise<{ witness: Uint8Array }>;
  }
}

declare module "@provekit-v1/acvm_js" {
  export function decompressWitnessStack(
    witness: Uint8Array,
  ): Array<{ witness: Map<number | string | { inner?: unknown }, unknown> }>;
}

declare module "provekit-sdk" {
  export type ProvingInput = Record<string, unknown>;
  export type BytesInput = Uint8Array | ArrayBuffer | ArrayBufferView | RequestInfo | URL | string;

  export interface WitnessProvider {
    generateWitness(
      inputs: ProvingInput,
      circuit: unknown,
    ): Promise<Record<string, unknown> | Map<number | string, unknown>>;
  }

  export interface ProvingModules {
    witness: BytesInput;
    derivatives: BytesInput;
  }

  export interface ProveKitWasmBindings {
    Prover: new (proverData: Uint8Array) => unknown;
    Verifier: new (verifierData: Uint8Array) => unknown;
    initPanicHook?: () => void;
    initThreadPool?: (numThreads: number) => Promise<unknown>;
  }

  export interface ProveKitInitOptions {
    bindings: ProveKitWasmBindings;
    init?: (moduleOrPath?: unknown) => Promise<unknown>;
    wasmModule?: unknown;
    threads?: number | false;
    panicHook?: boolean;
  }

  export interface LoadArtifactsOptions {
    baseUrl?: string | URL;
    prover?: BytesInput;
    verifier?: BytesInput;
    skipVerifier?: boolean;
    provingModules?: ProvingModules;
    witnessProvider?: WitnessProvider;
  }

  export class Proof {
    readonly bytes: Uint8Array;
    readonly data: Uint8Array;
    readonly size: number;
    json<T = unknown>(): T;
    text(): string;
  }

  export class ProveKitScheme {
    readonly numConstraints?: number;
    readonly numWitnesses?: number;
    readonly consumed: boolean;
    serializeProver(): Uint8Array;
    serializeVerifier(): Uint8Array | undefined;
    prove(inputs: ProvingInput): Promise<Proof>;
    verify(proof: Proof | Uint8Array): Promise<void>;
    tryVerify(proof: Proof | Uint8Array): Promise<boolean>;
    dispose(): void;
  }

  export class ProveKit {
    loadArtifacts(input: LoadArtifactsOptions | string | URL): Promise<ProveKitScheme>;
  }

  export function createProveKit(options: ProveKitInitOptions): Promise<ProveKit>;
}
