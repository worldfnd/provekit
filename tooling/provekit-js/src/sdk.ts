import { createMavrosRunner, type CompiledModuleRunner } from "./mavros-runner.js";
import { Proof } from "./proof.js";
import type {
  BytesInput,
  LoadArtifactsInput,
  LoadArtifactsOptions,
  ProveKitInitOptions,
  ProveKitWasmBindings,
  ProvingModules,
  ProvingInput,
  WitnessProvider,
} from "./types.js";

type ProverKind = "noir" | "mavros";

interface ProveKitWasmProver {
  free(): void;
  getProverKind(): string;
  getCircuit?(): Uint8Array;
  proveBytes?(witnessMap: Record<string, unknown> | Map<number | string, unknown>): Uint8Array;
  proveMavrosBytes?(inputs: ProvingInput, runner: CompiledModuleRunner): Uint8Array;
}

interface ProveKitWasmVerifier {
  free(): void;
  verifyBytes(proofJson: Uint8Array): void;
}

export async function createProveKit(options: ProveKitInitOptions): Promise<ProveKit> {
  if (options.init) {
    await options.init(options.wasmModule);
  }
  if (options.panicHook !== false) {
    options.bindings.initPanicHook?.();
  }
  if (options.threads !== false && options.bindings.initThreadPool) {
    const threads = options.threads ?? defaultThreadCount();
    await options.bindings.initThreadPool(threads);
  }
  return ProveKit.__create(options.bindings);
}

export async function fetchBytes(input: BytesInput): Promise<Uint8Array> {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  const response = await fetch(input);
  if (!response.ok) {
    throw new Error(`Failed to fetch ${String(input)}: ${response.status} ${response.statusText}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

export class ProveKit {
  private constructor(private readonly bindings: ProveKitWasmBindings) {}

  /** @internal Use {@link createProveKit} instead. */
  static __create(bindings: ProveKitWasmBindings): ProveKit {
    return new ProveKit(bindings);
  }

  async loadArtifacts(input: LoadArtifactsInput): Promise<ProveKitScheme> {
    const options = normalizeLoadArtifactsInput(input);
    const proverInput = options.prover ?? artifactFromBaseUrl(options.baseUrl, "prover.pkp");
    if (!proverInput) {
      throw new Error("loadArtifacts requires either a baseUrl or a prover artifact.");
    }
    const verifierInput = options.skipVerifier
      ? undefined
      : options.verifier ?? artifactFromBaseUrl(options.baseUrl, "verifier.pkv");
    const [proverBytes, verifierBytes] = await Promise.all([
      fetchBytes(proverInput),
      verifierInput ? fetchBytes(verifierInput) : Promise.resolve<Uint8Array | undefined>(undefined),
    ]);

    const prover = new this.bindings.Prover(proverBytes) as ProveKitWasmProver;
    let verifier: ProveKitWasmVerifier | undefined;
    try {
      verifier = verifierBytes
        ? new this.bindings.Verifier(verifierBytes) as ProveKitWasmVerifier
        : undefined;
      const kind = normalizeProverKind(prover.getProverKind());
      const provingModules = options.provingModules ?? provingModulesFromBaseUrl(options.baseUrl);
      const runner = kind === "mavros"
        ? await this.loadProvingModules(kind, provingModules)
        : undefined;
      if (kind === "mavros" && !runner) {
        throw new Error("This prover requires provingModules.program (or legacy witness and derivatives modules).");
      }
      if (kind === "noir" && !options.witnessProvider) {
        throw new Error("This prover requires a witnessProvider.");
      }
      return ProveKitScheme.__create({
        proverBytes,
        verifierBytes,
        prover,
        verifier,
        usesCompiledModules: kind === "mavros",
        runner,
        witnessProvider: options.witnessProvider,
      });
    } catch (error) {
      prover.free();
      verifier?.free();
      throw error;
    }
  }

  private async loadProvingModules(
    kind: ProverKind,
    modules: ProvingModules | undefined,
  ): Promise<CompiledModuleRunner> {
    if (kind !== "mavros") {
      throw new Error("provingModules were provided, but this prover does not use them.");
    }
    if (!modules) {
      throw new Error("This prover requires compiled proving modules. Provide a standard artifact directory or provingModules.");
    }
    if (modules.program) {
      try {
        return createMavrosRunner(await fetchBytes(modules.program));
      } catch (error) {
        if (!modules.witness || !modules.derivatives) {
          throw error;
        }
      }
    }
    if (!modules.witness || !modules.derivatives) {
      throw new Error("Mavros proving modules require program, or both witness and derivatives.");
    }
    const [witgenWasm, adWasm] = await Promise.all([
      fetchBytes(modules.witness),
      fetchBytes(modules.derivatives),
    ]);
    return createMavrosRunner(witgenWasm, adWasm);
  }
}

interface SchemeState {
  proverBytes: Uint8Array;
  verifierBytes?: Uint8Array;
  prover: ProveKitWasmProver;
  verifier?: ProveKitWasmVerifier;
  usesCompiledModules: boolean;
  runner?: CompiledModuleRunner;
  witnessProvider?: WitnessProvider;
}

export class ProveKitScheme {
  private readonly usesCompiledModules: boolean;
  private prover: ProveKitWasmProver | undefined;
  private verifier: ProveKitWasmVerifier | undefined;
  private readonly proverBytes: Uint8Array;
  private readonly verifierBytes?: Uint8Array;
  private readonly runner?: CompiledModuleRunner;
  private readonly witnessProvider?: WitnessProvider;

  private constructor(state: SchemeState) {
    this.usesCompiledModules = state.usesCompiledModules;
    this.proverBytes = new Uint8Array(state.proverBytes);
    this.verifierBytes = state.verifierBytes ? new Uint8Array(state.verifierBytes) : undefined;
    this.prover = state.prover;
    this.verifier = state.verifier;
    this.runner = state.runner;
    this.witnessProvider = state.witnessProvider;
  }

  /** @internal Created by {@link ProveKit.loadArtifacts}. */
  static __create(state: SchemeState): ProveKitScheme {
    return new ProveKitScheme(state);
  }

  get consumed(): boolean {
    return this.prover === undefined;
  }

  serializeProver(): Uint8Array {
    return new Uint8Array(this.proverBytes);
  }

  serializeVerifier(): Uint8Array | undefined {
    return this.verifierBytes ? new Uint8Array(this.verifierBytes) : undefined;
  }

  async prove(inputs: ProvingInput): Promise<Proof> {
    const prover = this.takeProver();
    try {
      if (this.usesCompiledModules) {
        if (!this.runner || !prover.proveMavrosBytes) {
          throw new Error("This prover is missing its proving modules.");
        }
        return Proof.fromBytes(prover.proveMavrosBytes(inputs, this.runner));
      }

      if (!prover.getCircuit || !prover.proveBytes || !this.witnessProvider) {
        throw new Error("This prover is missing getCircuit/proveBytes or a witnessProvider.");
      }
      const circuit = JSON.parse(new TextDecoder().decode(prover.getCircuit())) as unknown;
      const witness = await this.witnessProvider.generateWitness(inputs, circuit);
      return Proof.fromBytes(prover.proveBytes(witness));
    } finally {
      prover.free();
    }
  }

  /**
   * Verify a proof. Throws if verification fails or if the verifier rejects
   * the proof. Use `tryVerify` if you want a boolean result.
   */
  async verify(proof: Proof | Uint8Array): Promise<void> {
    if (!this.verifier) {
      throw new Error("No verifier artifact was loaded.");
    }
    const proofBytes = proof instanceof Proof ? proof.bytes : proof;
    this.verifier.verifyBytes(proofBytes);
  }

  /**
   * Verify a proof and return `true` on success, `false` if the verifier
   * rejects it. Throws for setup errors (e.g. no verifier loaded).
   */
  async tryVerify(proof: Proof | Uint8Array): Promise<boolean> {
    if (!this.verifier) {
      throw new Error("No verifier artifact was loaded.");
    }
    const proofBytes = proof instanceof Proof ? proof.bytes : proof;
    try {
      this.verifier.verifyBytes(proofBytes);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Release any remaining WASM-side handles. Safe to call multiple times,
   * and safe to call after `prove()` (which already consumes the prover).
   */
  dispose(): void {
    this.prover?.free();
    this.prover = undefined;
    this.verifier?.free();
    this.verifier = undefined;
  }

  private takeProver(): ProveKitWasmProver {
    const prover = this.prover;
    if (!prover) {
      throw new Error("This prover has already been consumed. Load artifacts again to prove another input.");
    }
    this.prover = undefined;
    return prover;
  }
}

function normalizeProverKind(kind: string): ProverKind {
  if (kind === "noir" || kind === "mavros") {
    return kind;
  }
  throw new Error(`Unsupported ProveKit prover kind: ${kind}`);
}

function normalizeLoadArtifactsInput(input: LoadArtifactsInput): LoadArtifactsOptions {
  if (typeof input === "string" || input instanceof URL) {
    return { baseUrl: input };
  }
  return input;
}

function provingModulesFromBaseUrl(baseUrl: string | URL | undefined): ProvingModules | undefined {
  if (!baseUrl) {
    return undefined;
  }
  return {
    program: joinBaseUrl(baseUrl, "program.wasm"),
    witness: joinBaseUrl(baseUrl, "witgen.wasm"),
    derivatives: joinBaseUrl(baseUrl, "ad.wasm"),
  };
}

function artifactFromBaseUrl(baseUrl: string | URL | undefined, fileName: string): BytesInput | undefined {
  if (!baseUrl) {
    return undefined;
  }
  return joinBaseUrl(baseUrl, fileName);
}

function joinBaseUrl(baseUrl: string | URL, fileName: string): string {
  const base = String(baseUrl);
  return `${base.endsWith("/") ? base : `${base}/`}${fileName}`;
}

function defaultThreadCount(): number {
  const hardwareConcurrency = globalThis.navigator?.hardwareConcurrency;
  return Math.max(1, hardwareConcurrency ?? 1);
}
