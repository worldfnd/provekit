import {
  initProveKit,
  ProveKitError,
  ProveKitErrorCode,
} from "@worldcoin/provekit";

type ThreadSetting = "auto" | false;

interface AcceptanceResult {
  requestedThreads: ThreadSetting;
  mode: "single" | "threaded";
  threads: number;
  valid: boolean;
  proofBytes: number;
  legacyErrorCode: string;
}

declare global {
  interface Window {
    runProveKit(threadSetting: ThreadSetting): Promise<AcceptanceResult>;
  }
}

window.runProveKit = async (threadSetting) => {
  const runtime = await initProveKit({ threads: threadSetting });
  const [proverBytes, verifierBytes, inputs] = await Promise.all([
    fetch("/artifacts/prover.pkp").then(async (response) => new Uint8Array(await response.arrayBuffer())),
    fetch("/artifacts/verifier.pkv").then(async (response) => new Uint8Array(await response.arrayBuffer())),
    fetch("/artifacts/inputs.json").then(async (response) => response.json() as Promise<Record<string, unknown>>),
  ]);
  const prover = await runtime.loadProver(proverBytes);
  const verifier = await runtime.loadVerifier(verifierBytes);
  try {
    let proof;
    try {
      proof = await prover.prove(inputs);
    } catch (error) {
      const messages: string[] = [];
      let current: unknown = error;
      while (current instanceof Error) {
        messages.push(current.message);
        current = current.cause;
      }
      throw new Error(messages.join(": "), { cause: error });
    }
    const valid = await verifier.verify(proof);
    const legacy = proverBytes.slice(0, 21);
    legacy[16] = 1;
    legacy[17] = 0;
    legacy[18] = 1;
    legacy[19] = 0;
    let legacyErrorCode = "";
    try {
      await runtime.loadProver(legacy);
    } catch (error) {
      if (!(error instanceof ProveKitError)) throw error;
      legacyErrorCode = error.code;
    }
    if (legacyErrorCode !== ProveKitErrorCode.ARTIFACT_VERSION) {
      throw new Error(`Expected ARTIFACT_VERSION, received ${legacyErrorCode || "no error"}`);
    }
    return {
      requestedThreads: threadSetting,
      mode: runtime.threading.mode,
      threads: runtime.threading.threads,
      valid,
      proofBytes: proof.size,
      legacyErrorCode,
    };
  } finally {
    prover.dispose();
    verifier.dispose();
  }
};
