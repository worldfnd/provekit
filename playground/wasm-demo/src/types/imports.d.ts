declare module "provekit-inspector" {
  export default function initProvekitInspector(): Promise<void>;

  export class Prover {
    constructor(bytes: Uint8Array);
    getNumConstraints(): number;
    getNumWitnesses(): number;
    free(): void;
  }
}
