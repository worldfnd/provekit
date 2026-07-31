import { resolve } from "node:path";

import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";

interface CircuitArtifact {
  bytecode: string;
  [key: string]: unknown;
}

interface ProofData {
  proof: Uint8Array;
  publicInputs: string[];
}

const dist = resolve(Bun.argv[2] ?? "web/dist");
const workloads = [
  "webauthn_assertion",
  "passport_complete_age_check",
  "oprf_taceo",
  "oprf_world_id_nullifier",
] as const;
type Workload = (typeof workloads)[number];

const workload = Bun.argv[3] as Workload | undefined;
if (!workload || !workloads.includes(workload)) {
  throw new Error(`usage: bun run generate-web-fixtures.ts <dist> <${workloads.join("|")}>`);
}

const assetDirectory = resolve(dist, "assets", workload);
const circuit = (await Bun.file(resolve(assetDirectory, "circuit.json")).json()) as CircuitArtifact;
const inputs = (await Bun.file(resolve(assetDirectory, "inputs.json")).json()) as Record<
  string,
  unknown
>;
const noir = new Noir(circuit);
const api = await Barretenberg.new({ threads: 1 });
const backend = new UltraHonkBackend(circuit.bytecode, api);

try {
  const witness = (await noir.execute(inputs)).witness;
  const proof = (await backend.generateProof(witness)) as ProofData;
  if (!(await backend.verifyProof(proof))) {
    throw new Error(`Barretenberg rejected generated ${workload} fixture`);
  }
  await Promise.all([
    Bun.write(resolve(assetDirectory, "witness.gz"), witness),
    Bun.write(resolve(assetDirectory, "proof.bin"), proof.proof),
    Bun.write(
      resolve(assetDirectory, "public-inputs.json"),
      `${JSON.stringify(proof.publicInputs)}\n`,
    ),
  ]);
  console.log(
    `Generated ${workload}: witness=${witness.byteLength} proof=${proof.proof.byteLength}`,
  );
} finally {
  await api.destroy().catch(() => undefined);
  const destroy = (noir as Noir & { destroy?: () => Promise<void> | void }).destroy;
  if (destroy) await Promise.resolve(destroy.call(noir)).catch(() => undefined);
}

process.exit(0);
