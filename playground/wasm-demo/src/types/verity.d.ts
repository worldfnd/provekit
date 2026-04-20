declare module "@atheonxyz/verity" {
  export enum Backend {
    ProveKit = 0,
    Barretenberg = 1,
  }

  export interface BackendOptions {
    wasmUrl?: string;
    threads?: number | false;
  }

  export class Proof {
    readonly data: Uint8Array;
    readonly size: number;
    readonly hex: string;
    hexPreview(maxBytes?: number): string;
    static fromBytes(data: Uint8Array): Proof;
  }

  export interface ProverScheme {
    prove(inputs: Record<string, unknown> | string): Promise<Proof>;
    serialize(): Promise<Uint8Array>;
    dispose(): void;
  }

  export interface VerifierScheme {
    verify(proof: Proof): Promise<boolean>;
    serialize(): Promise<Uint8Array>;
    dispose(): void;
  }

  export class Verity {
    static create(backend: Backend, options?: BackendOptions): Promise<Verity>;
    loadProver(data: Uint8Array): Promise<ProverScheme>;
    loadVerifier(data: Uint8Array): Promise<VerifierScheme>;
    prove(prover: ProverScheme, inputs: Record<string, unknown> | string): Promise<Proof>;
    verify(verifier: VerifierScheme, proof: Proof): Promise<boolean>;
  }
}
