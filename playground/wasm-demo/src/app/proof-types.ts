export class Proof {
  readonly data: Uint8Array;
  readonly size: number;

  private constructor(data: Uint8Array) {
    this.data = data;
    this.size = data.byteLength;
  }

  static fromBytes(data: Uint8Array): Proof {
    return new Proof(new Uint8Array(data));
  }
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
