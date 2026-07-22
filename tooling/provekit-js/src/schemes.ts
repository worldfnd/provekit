import type { ArtifactLimits } from "./artifacts.js";
import { ProveKitError, ProveKitErrorCode, mapRuntimeError } from "./errors.js";
import { Proof, proofBytesForVerification } from "./proof.js";
import type { ProveKitWasmModule, WasmVerifierHandle } from "./wasm-types.js";
import { convertWitnessMap, executeNoirWitness } from "./witness.js";

type CircuitInputs = Record<string, unknown> | string;

function assertNotDisposed(disposed: boolean, resource: string): void {
  if (disposed) {
    throw new ProveKitError(ProveKitErrorCode.DISPOSED, `${resource} has been disposed`);
  }
}

function parseInputs(inputs: CircuitInputs): Record<string, unknown> {
  let parsed: unknown = inputs;
  if (typeof inputs === "string") {
    try {
      parsed = JSON.parse(inputs) as unknown;
    } catch (error) {
      throw new ProveKitError(ProveKitErrorCode.INVALID_ARGUMENT, "Inputs are not valid JSON", {
        cause: error,
      });
    }
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ProveKitError(
      ProveKitErrorCode.INVALID_ARGUMENT,
      "Circuit inputs must be an object or a JSON object string",
    );
  }
  return parsed as Record<string, unknown>;
}

export interface Prover {
  prove(inputs: CircuitInputs): Promise<Proof>;
  serialize(): Uint8Array;
  dispose(): void;
}

export interface Verifier {
  verify(proof: Proof): Promise<boolean>;
  serialize(): Uint8Array;
  dispose(): void;
}

export class ProveKitProver implements Prover {
  #disposed = false;
  #artifact: Uint8Array;
  #circuit: unknown;

  constructor(
    private readonly module: ProveKitWasmModule,
    artifact: Uint8Array,
    circuit: unknown,
    private readonly limits: ArtifactLimits,
  ) {
    this.#artifact = new Uint8Array(artifact);
    this.#circuit = circuit;
  }

  async prove(inputs: CircuitInputs): Promise<Proof> {
    assertNotDisposed(this.#disposed, "Prover");
    const execution = await executeNoirWitness(this.#circuit, parseInputs(inputs));
    let converted: Record<string, string> | undefined;
    let handle: InstanceType<ProveKitWasmModule["Prover"]> | undefined;
    try {
      converted = convertWitnessMap(execution.witnessMap);
      handle = new this.module.Prover(this.#artifact);
      const proofBytes = handle.proveBytes(converted);
      return Proof.fromBytes(proofBytes, this.limits.maxProofBytes);
    } catch (error) {
      throw mapRuntimeError(error, ProveKitErrorCode.PROVING_FAILED, "ProveKit proving failed");
    } finally {
      handle?.free();
      if (converted) {
        for (const key of Object.keys(converted)) converted[key] = "0x0";
      }
      execution.release();
    }
  }

  serialize(): Uint8Array {
    assertNotDisposed(this.#disposed, "Prover");
    return new Uint8Array(this.#artifact);
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#artifact.fill(0);
    this.#artifact = new Uint8Array();
    this.#circuit = null;
  }
}

export class ProveKitVerifier implements Verifier {
  #disposed = false;
  #artifact: Uint8Array;
  #handle: WasmVerifierHandle | null;

  constructor(handle: WasmVerifierHandle, artifact: Uint8Array, private readonly limits: ArtifactLimits) {
    this.#handle = handle;
    this.#artifact = new Uint8Array(artifact);
  }

  async verify(proof: Proof): Promise<boolean> {
    assertNotDisposed(this.#disposed, "Verifier");
    if (!(proof instanceof Proof)) {
      throw new ProveKitError(ProveKitErrorCode.MALFORMED_PROOF, "verify() requires a Proof");
    }
    const proofBytes = proofBytesForVerification(proof, this.limits);
    try {
      return this.#handle?.verifyBytes(proofBytes) ?? false;
    } catch (error) {
      throw mapRuntimeError(
        error,
        ProveKitErrorCode.PROVING_FAILED,
        "ProveKit verification failed",
      );
    }
  }

  serialize(): Uint8Array {
    assertNotDisposed(this.#disposed, "Verifier");
    return new Uint8Array(this.#artifact);
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#handle?.free();
    this.#handle = null;
    this.#artifact.fill(0);
    this.#artifact = new Uint8Array();
  }
}
