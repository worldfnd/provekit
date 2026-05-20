declare module "provekit-inspector" {
  export default function initProvekitInspector(): Promise<void>;
  export function initPanicHook(): void;
  export function initThreadPool(numThreads: number): Promise<void>;

  export class Prover {
    constructor(bytes: Uint8Array);
    getNumConstraints(): number;
    getNumWitnesses(): number;
    free(): void;
  }
}
