import type { ProverScheme, VerifierScheme } from "@atheonxyz/verity";

import { ArtifactLoader } from "./app/artifact-loader.js";
import { ChecklistPresenter } from "./app/checklist.js";
import { CircuitController } from "./app/circuit-controller.js";
import { collectDom } from "./app/dom.js";
import { LogRenderer } from "./app/logs.js";
import { ProofOutputPresenter } from "./app/proof-output.js";
import { initializeRuntime, readCircuitStatsFromPkp } from "./app/proof-runtime.js";
import { RunController } from "./app/run-controller.js";
import { StepPresenter, stepStatus } from "./app/steps.js";
import type { AppState } from "./app/types.js";
import { VerifyController } from "./app/verify-controller.js";

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

class DemoApp {
  private readonly dom = collectDom(document);
  private readonly logs = new LogRenderer(this.dom.logContainer);
  private readonly steps = new StepPresenter(this.dom.steps);
  private readonly checklist = new ChecklistPresenter(this.dom.checklist);
  private readonly proofOutput = new ProofOutputPresenter(this.dom, this.logs);
  private readonly state: AppState = {
    activeCircuit: "sha256",
    customFiles: {},
    wasmReady: false,
    runtime: null,
    lastProof: null,
    activeVerifier: null,
  };
  private readonly artifacts = new ArtifactLoader({
    log: (message, type) => this.logs.log(message, type),
    logMemory: (label, extras) => this.logMemory(label, extras),
  }, readCircuitStatsFromPkp);
  private readonly circuits = new CircuitController({
    dom: this.dom,
    state: this.state,
    logs: this.logs,
    steps: this.steps,
    checklist: this.checklist,
    proofOutput: this.proofOutput,
    disposeActiveVerifier: () => this.disposeActiveVerifier(),
  });
  private readonly runner = new RunController({
    dom: this.dom,
    state: this.state,
    logs: {
      log: (message, type) => this.logs.log(message, type),
      logMemory: (label, extras) => this.logMemory(label, extras),
      clear: () => this.logs.clear(),
    },
    steps: this.steps,
    proofOutput: this.proofOutput,
    artifacts: this.artifacts,
    loadSchemes: (proverBytes, verifierBytes) => this.loadSchemes(proverBytes, verifierBytes),
    waitForUi: () => this.waitForUi(),
    disposeActiveVerifier: () => this.disposeActiveVerifier(),
    refreshRunButton: () => this.circuits.refreshRunButton(),
  });
  private readonly verifier = new VerifyController({
    dom: this.dom,
    state: this.state,
    logs: this.logs,
    steps: this.steps,
    waitForUi: () => this.waitForUi(),
  });

  constructor() {
    this.bindEvents();
    this.circuits.applyCircuit("sha256", false);
    void this.initialize();
  }

  private bindEvents(): void {
    this.dom.runButton.addEventListener("click", () => {
      void this.runner.run();
    });
    this.dom.verifyButton.addEventListener("click", () => {
      void this.verifier.verify();
    });
    this.dom.copyLogsButton.addEventListener("click", () => {
      void this.copyLogs();
    });
    this.circuits.bind();
  }

  private async initialize(): Promise<void> {
    try {
      this.steps.setStatus(1, stepStatus.running("Loading..."));
      this.logs.log("Initializing proof runtime...");
      this.state.runtime = await initializeRuntime(this.logs);
      this.state.wasmReady = true;
      this.steps.setStatus(1, stepStatus.success("Loaded"));
      this.circuits.refreshRunButton();
    } catch (error) {
      this.logs.log(`Error initializing proof runtime: ${getErrorMessage(error)}`, "error");
      this.steps.setStatus(1, stepStatus.error("Failed"));
      console.error(error);
    }
  }

  private disposeActiveVerifier(): void {
    this.state.activeVerifier?.dispose();
    this.state.activeVerifier = null;
  }

  private logMemory(label: string, extras: Record<string, unknown> = {}): void {
    let message = `📊 ${label}`;

    for (const [name, value] of Object.entries(extras)) {
      if (value instanceof ArrayBuffer) {
        message += ` | ${name}: ${(value.byteLength / 1024 / 1024).toFixed(2)} MB`;
      } else if (value instanceof Uint8Array) {
        message += ` | ${name}: ${(value.byteLength / 1024 / 1024).toFixed(2)} MB`;
      } else if (typeof value === "object" && value !== null) {
        message += ` | ${name}: ~${(JSON.stringify(value).length / 1024).toFixed(0)} KB`;
      }
    }

    const maybePerformance = performance as Performance & { memory?: { usedJSHeapSize: number } };
    if (maybePerformance.memory) {
      message += ` | heap: ${(maybePerformance.memory.usedJSHeapSize / 1024 / 1024).toFixed(1)} MB`;
    }

    this.logs.log(message);
  }

  private async waitForUi(): Promise<void> {
    await new Promise((resolve) => window.setTimeout(resolve, 50));
  }

  private async loadSchemes(proverBytes: Uint8Array, verifierBytes: Uint8Array): Promise<{
    prover: ProverScheme;
    verifier: VerifierScheme;
  }> {
    if (!this.state.runtime) {
      throw new Error("Proof runtime is not initialized yet.");
    }

    this.logs.log("Loading prover and verifier...");
    const loadStart = performance.now();

    // Use allSettled so we can dispose the resolved scheme if the other load
    // rejects — a bare Promise.all would leak the fulfilled side's WASM handle.
    const [proverResult, verifierResult] = await Promise.allSettled([
      this.state.runtime.loadProver(proverBytes),
      this.state.runtime.loadVerifier(verifierBytes),
    ]);

    if (proverResult.status === "rejected" || verifierResult.status === "rejected") {
      if (proverResult.status === "fulfilled") {
        proverResult.value.dispose();
      }
      if (verifierResult.status === "fulfilled") {
        verifierResult.value.dispose();
      }
      throw proverResult.status === "rejected"
        ? proverResult.reason
        : (verifierResult as PromiseRejectedResult).reason;
    }

    this.logs.log(`Scheme load time: ${(performance.now() - loadStart).toFixed(0)}ms`);
    return { prover: proverResult.value, verifier: verifierResult.value };
  }

  private async copyLogs(): Promise<void> {
    try {
      await this.logs.copyToClipboard();
      const originalHtml = this.dom.copyLogsButton.innerHTML;
      const originalStroke = this.dom.copyLogsButton.getAttribute("stroke");
      this.dom.copyLogsButton.innerHTML = `<polyline points="20 6 9 17 4 12"></polyline>`;
      this.dom.copyLogsButton.setAttribute("stroke", "var(--accent-cyan)");
      window.setTimeout(() => {
        this.dom.copyLogsButton.innerHTML = originalHtml;
        if (originalStroke) {
          this.dom.copyLogsButton.setAttribute("stroke", originalStroke);
        }
      }, 2000);
    } catch (error) {
      console.error("Failed to copy logs:", error);
    }
  }
}

new DemoApp();
