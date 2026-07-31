type ProofData = { proof: Uint8Array; publicInputs: string[] };

async function loadJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`failed to fetch ${path}: HTTP ${response.status}`);
  return await response.json() as T;
}

function durationNs(start: number): number {
  return Math.round((performance.now() - start) * 1_000_000);
}

async function run(warmup: number, iterations: number): Promise<unknown> {
  // Expose the runner before loading the large WASM-backed modules. This lets
  // the harness distinguish module initialization from proving failures.
  const [{ BackendType, Barretenberg, UltraHonkBackend }, { Noir }] = await Promise.all([
    import("./vendor/bb/index.js"),
    import("@noir-lang/noir_js"),
  ]);
  const [circuit, inputs] = await Promise.all([
    loadJson<{ bytecode: string }>("./assets/passport_p1/circuit.json"),
    loadJson<Record<string, unknown>>("./assets/passport_p1/inputs.json"),
  ]);
  const noir = new Noir(circuit);
  const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1 });
  const backend = new UltraHonkBackend(circuit.bytecode, api);
  try {
    const witness = (await noir.execute(inputs)).witness;
    const canary = await backend.generateProof(witness) as ProofData;
    if (!(await backend.verifyProof(canary))) throw new Error("Barretenberg rejected the P1 canary proof");
    const tampered = canary.proof.slice();
    tampered[Math.floor(tampered.byteLength / 2)] ^= 1;
    let tamperedProofRejected = false;
    try {
      tamperedProofRejected = !(await backend.verifyProof({ ...canary, proof: tampered }));
    } catch {
      tamperedProofRejected = true;
    }
    if (!tamperedProofRejected) throw new Error("Barretenberg accepted a tampered P1 proof");

    const samples: Array<{ warmup: boolean; sample_index: number; prove_time_ns: number }> = [];
    for (let run = 0; run < warmup + iterations; run += 1) {
      const started = performance.now();
      const proof = await backend.generateProof(witness) as ProofData;
      if (!(await backend.verifyProof(proof))) throw new Error("Barretenberg rejected a P1 sample proof");
      samples.push({ warmup: run < warmup, sample_index: run < warmup ? run : run - warmup, prove_time_ns: durationNs(started) });
    }
    return {
      workload: "passport_p1",
      backend: "barretenberg_4.2.0-aztecnr-rc.2_wasm_single",
      warmup,
      iterations,
      samples,
      proof_size_bytes: canary.proof.byteLength,
      public_inputs: canary.publicInputs,
      tampered_proof_rejected: tamperedProofRejected,
      user_agent: navigator.userAgent,
    };
  } finally {
    await api.destroy();
    const destroy = (noir as typeof noir & { destroy?: () => Promise<void> | void }).destroy;
    if (destroy) await destroy.call(noir);
  }
}

Object.assign(window, { passportP1: { run } });
