import { UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { loadNoirInputs } from "./load-inputs";

const workloads = {
  webauthn_assertion: {
    circuitUrl: new URL(
      "../noir/webauthn_assertion/target/webauthn_assertion.json",
      import.meta.url,
    ),
    inputsUrl: new URL("../noir/webauthn_assertion/inputs.json", import.meta.url),
  },
  passport_complete_age_check: {
    circuitUrl: new URL(
      "../../../noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.json",
      import.meta.url,
    ),
    inputsUrl: new URL(
      "../../../noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml",
      import.meta.url,
    ),
  },
  oprf_taceo: {
    circuitUrl: new URL(
      "../../../target/v1-benchmarks/sources/oprf-nr/oprf_example/target/oprf_example.json",
      import.meta.url,
    ),
    inputsUrl: new URL(
      "../../../target/v1-benchmarks/sources/oprf-nr/oprf_example/Prover.toml",
      import.meta.url,
    ),
  },
} as const;

const workloadName = Bun.argv[2] as keyof typeof workloads | undefined;
if (!workloadName || !(workloadName in workloads)) {
  throw new Error(`workload must be one of: ${Object.keys(workloads).join(", ")}`);
}
const { circuitUrl, inputsUrl } = workloads[workloadName];
const circuit = (await Bun.file(circuitUrl).json()) as {
  bytecode: string;
  [key: string]: unknown;
};
const inputs = await loadNoirInputs(inputsUrl);

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
  if (!verified) throw new Error(`Barretenberg rejected its ${workloadName} proof`);

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
    throw new Error(`Barretenberg accepted a tampered ${workloadName} proof`);
  }

  console.log(
    JSON.stringify(
      {
        schema_version: 1,
        benchmark: workloadName,
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
