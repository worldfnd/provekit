import type { DemoDom } from "./dom.js";
import { StepPresenter, stepStatus } from "./steps.js";
import type { AppState, LogWriter } from "./types.js";

interface VerifyControllerDeps {
  dom: DemoDom;
  state: AppState;
  logs: LogWriter;
  steps: StepPresenter;
  waitForUi(): Promise<void>;
}

export class VerifyController {
  constructor(private readonly deps: VerifyControllerDeps) {}

  async verify(): Promise<void> {
    const { dom, logs, state, steps } = this.deps;
    if (!state.lastProof || !state.activeVerifier) {
      logs.log("No proof available. Generate a proof first.", "error");
      return;
    }

    dom.verifyButton.disabled = true;

    try {
      steps.setStatus(5, stepStatus.running("Verifying..."));
      logs.log("Verifying proof...");
      await this.deps.waitForUi();

      const verifyStart = performance.now();
      const isValid = await state.activeVerifier.verify(state.lastProof);
      const verifyTime = performance.now() - verifyStart;

      logs.log(`Verification time: ${verifyTime.toFixed(0)}ms`);
      if (!isValid) {
        logs.log("Proof is invalid.", "error");
        steps.setStatus(5, stepStatus.error(`Invalid (${verifyTime.toFixed(0)}ms)`));
        return;
      }

      logs.log("Proof verified successfully!", "success");
      steps.setStatus(5, stepStatus.success(`Verified ✓ (${verifyTime.toFixed(0)}ms)`));
    } catch (error) {
      logs.log(`Verification error: ${error instanceof Error ? error.message : String(error)}`, "error");
      steps.setStatus(5, stepStatus.error("Failed"));
      console.error(error);
    } finally {
      dom.verifyButton.disabled = false;
    }
  }
}
