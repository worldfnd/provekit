import { UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";

const circuitUrl = new URL("../noir/webauthn_assertion/target/webauthn_assertion.json", import.meta.url);
const inputsUrl = new URL("../noir/webauthn_assertion/inputs.json", import.meta.url);
const circuit = (await Bun.file(circuitUrl).json()) as {
  bytecode: string;
  [key: string]: unknown;
};
const inputs = (await Bun.file(inputsUrl).json()) as Record<string, unknown>;

const noir = new Noir(circuit);
const witnessStart = performance.now();
const execution = await noir.execute(inputs);
const witnessTimeMs = performance.now() - witnessStart;

const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 });
try {
  const proveStart = performance.now();
  const proof = await backend.generateProof(execution.witness);
  const proveTimeMs = performance.now() - proveStart;

  const verifyStart = performance.now();
  const verified = await backend.verifyProof(proof);
  const verifyTimeMs = performance.now() - verifyStart;
  if (!verified) throw new Error("Barretenberg rejected its WebAuthn proof");

  const tamperedProofBytes = proof.proof.slice();
  tamperedProofBytes[Math.floor(tamperedProofBytes.byteLength / 2)] ^= 1;
  let tamperedProofRejected = false;
  try {
    tamperedProofRejected = !(await backend.verifyProof({
      ...proof,
      proof: tamperedProofBytes,
    }));
  } catch {
    tamperedProofRejected = true;
  }
  if (!tamperedProofRejected) {
    throw new Error("Barretenberg accepted a tampered WebAuthn proof");
  }

  console.log(
    JSON.stringify(
      {
        schema_version: 1,
        benchmark: "webauthn_assertion",
        backend: "barretenberg_0.87.0_single",
        witness_time_ms: witnessTimeMs,
        prove_time_ms: proveTimeMs,
        verify_time_ms: verifyTimeMs,
        proof_size_bytes: proof.proof.byteLength,
        public_input_count: proof.publicInputs.length,
        tampered_proof_rejected: tamperedProofRejected,
      },
      null,
      2,
    ),
  );
} finally {
  await backend.destroy();
  const destroy = (noir as Noir & { destroy?: () => Promise<void> | void }).destroy;
  if (destroy) await destroy.call(noir);
}
