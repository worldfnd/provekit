import type { ProverScheme, VerifierScheme } from "@atheonxyz/verity";

import { ArtifactLoader } from "./artifact-loader.js";
import type { DemoDom } from "./dom.js";
import { ProofOutputPresenter } from "./proof-output.js";
import { StepPresenter, stepStatus } from "./steps.js";
import type { AppState, DiagnosticsWriter } from "./types.js";

interface RunControllerDeps {
  dom: DemoDom;
  state: AppState;
  logs: DiagnosticsWriter & { clear(): void };
  steps: StepPresenter;
  proofOutput: ProofOutputPresenter;
  artifacts: ArtifactLoader;
  loadSchemes(proverBytes: Uint8Array, verifierBytes: Uint8Array): Promise<{
    prover: ProverScheme;
    verifier: VerifierScheme;
  }>;
  waitForUi(): Promise<void>;
  disposeActiveVerifier(): void;
  refreshRunButton(): void;
}

export class RunController {
  constructor(private readonly deps: RunControllerDeps) {}

  async run(): Promise<void> {
    if (!this.deps.state.runtime) {
      this.deps.logs.log("Proof runtime is not initialized yet.", "error");
      return;
    }

    this.resetRunState();

    let prover: ProverScheme | null = null;
    let verifier: VerifierScheme | null = null;
    let failingStep = 2;

    try {
      this.deps.steps.setStatus(2, stepStatus.running("Loading artifacts..."));
      const { proverBytes, verifierBytes, metadata } = await this.deps.artifacts.loadArtifacts(
        this.deps.state.activeCircuit,
        this.deps.state.customFiles,
      );

      ({ prover, verifier } = await this.deps.loadSchemes(proverBytes, verifierBytes));
      this.deps.steps.setStatus(2, stepStatus.success("Loaded"));

      failingStep = 3;
      this.deps.steps.setStatus(3, stepStatus.running("Preparing inputs..."));
      const inputs = await this.deps.artifacts.loadInputs(this.deps.state.activeCircuit, this.deps.state.customFiles);
      this.deps.logs.log(`Inputs loaded (${Object.keys(inputs).length} top-level keys)`);
      this.deps.logs.logMemory("After preparing inputs", { inputs });
      this.deps.steps.setStatus(3, stepStatus.success("Done"));

      failingStep = 4;
      this.deps.steps.setStatus(4, stepStatus.running("Generating proof..."));
      this.deps.logs.log("Generating proof...");
      this.deps.logs.logMemory("Before prove()", { proverBytes, inputs });
      await this.deps.waitForUi();

      const proofStart = performance.now();
      const proof = await prover.prove(inputs);
      const proofTime = performance.now() - proofStart;

      this.deps.logs.logMemory("After prove()", { proof: proof.data });
      this.deps.logs.log(`Proof size: ${(proof.size / 1024).toFixed(1)} KB`);
      this.deps.logs.log(`Proving time: ${(proofTime / 1000).toFixed(2)}s`);
      this.deps.proofOutput.renderProof(proof);
      this.deps.proofOutput.updateMetrics(metadata, proof.size, proofTime);

      // Transfer ownership of the verifier to state before any further work so
      // an exception in the UI updates below cannot cause a double-dispose.
      this.deps.state.lastProof = proof;
      this.deps.state.activeVerifier = verifier;
      verifier = null;

      this.deps.steps.setStatus(4, stepStatus.success(`Done (${(proofTime / 1000).toFixed(2)}s)`));
      this.deps.steps.setStatus(5, stepStatus.success("Ready — click Verify Proof"));
      this.deps.dom.verifyButton.disabled = false;
    } catch (error) {
      this.deps.logs.log(`Error: ${error instanceof Error ? error.message : String(error)}`, "error");
      this.deps.steps.setStatus(failingStep, stepStatus.error("Failed"));
      console.error(error);
      verifier?.dispose();
    } finally {
      prover?.dispose();
      this.deps.refreshRunButton();
    }
  }

  private resetRunState(): void {
    const { dom, logs, proofOutput, state, steps } = this.deps;
    dom.runButton.disabled = true;
    dom.verifyButton.disabled = true;
    logs.clear();
    // Reset steps 2–5 only; step 1 ("Load Proof Runtime") has already
    // completed and is tied to the long-lived Verity runtime, not per-run.
    steps.reset(2);
    proofOutput.reset();
    state.lastProof = null;
    this.deps.disposeActiveVerifier();
  }
}
