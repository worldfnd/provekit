import { decompressWitnessStack } from "@noir-lang/acvm_js";
import { Noir } from "@noir-lang/noir_js";
import * as ProvekitInspector from "provekit-inspector";
import { createProveKit, type ProveKit, type ProveKitScheme, type WitnessProvider, type Proof as SdkProof } from "provekit-sdk";

import { ArtifactLoader } from "./app/artifact-loader.js";
import { ChecklistPresenter } from "./app/checklist.js";
import { CircuitController } from "./app/circuit-controller.js";
import { collectDom } from "./app/dom.js";
import { LogRenderer } from "./app/logs.js";
import { Proof, type ProverScheme, type VerifierScheme } from "./app/proof-types.js";
import { ProofOutputPresenter } from "./app/proof-output.js";
import { initializeRuntime, readCircuitStatsFromPkp } from "./app/proof-runtime.js";
import { RunController } from "./app/run-controller.js";
import { StepPresenter, stepStatus } from "./app/steps.js";
import type { AppState } from "./app/types.js";
import { VerifyController } from "./app/verify-controller.js";

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

class BrowserWitnessProvider implements WitnessProvider {
  async generateWitness(inputs: Record<string, unknown>, circuit: unknown): Promise<Record<string, unknown>> {
    const noir = new Noir(circuit as never);
    const { witness: compressedWitness } = await noir.execute(inputs as never);
    const witnessStack = decompressWitnessStack(compressedWitness);
    const witnessMap = witnessStack[0]?.witness;
    if (!witnessMap) {
      throw new Error("Circuit execution produced an empty witness stack");
    }

    const converted: Record<string, unknown> = {};
    for (const [witness, value] of witnessMap.entries()) {
      const index = typeof witness === "number"
        ? witness
        : typeof (witness as { inner?: unknown })?.inner === "number"
          ? (witness as { inner: number }).inner
          : Number(witness);
      if (Number.isNaN(index)) {
        throw new Error(`Failed to extract witness index from key: ${String(witness)}`);
      }
      converted[index] = value;
    }
    return converted;
  }
}

function toLocalProof(sdkProof: SdkProof): Proof {
  return Proof.fromBytes(sdkProof.bytes);
}

class SdkProverScheme implements ProverScheme {
  constructor(private readonly scheme: ProveKitScheme) {}

  async prove(inputs: Record<string, unknown>): Promise<Proof> {
    return toLocalProof(await this.scheme.prove(inputs));
  }

  async serialize(): Promise<Uint8Array> {
    return this.scheme.serializeProver();
  }

  dispose(): void {
    // No-op: the SDK consumes the prover handle during prove(); the paired
    // SdkVerifierScheme owns final disposal of the scheme.
  }
}

class SdkVerifierScheme implements VerifierScheme {
  constructor(private readonly scheme: ProveKitScheme) {}

  async verify(proof: Proof): Promise<boolean> {
    return this.scheme.tryVerify(proof.data);
  }

  async serialize(): Promise<Uint8Array> {
    return this.scheme.serializeVerifier() ?? new Uint8Array();
  }

  dispose(): void {
    this.scheme.dispose();
  }
}

class DemoApp {
  private readonly dom = collectDom(document);
  private readonly logs = new LogRenderer(this.dom.logContainer);
  private readonly steps = new StepPresenter(this.dom.steps);
  private readonly checklist = new ChecklistPresenter(this.dom.checklist);
  private readonly proofOutput = new ProofOutputPresenter(this.dom, this.logs);
  private readonly witnessProvider = new BrowserWitnessProvider();
  private provekit: ProveKit | null = null;
  private readonly state: AppState = {
    activeCircuit: "sha256",
    customFiles: {},
    wasmReady: false,
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
    loadSchemes: (proverBytes, verifierBytes, mavrosArtifacts) => this.loadSchemes(proverBytes, verifierBytes, mavrosArtifacts),
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
      await initializeRuntime(this.logs);
      this.provekit = await createProveKit({
        bindings: ProvekitInspector,
        threads: false,
        panicHook: false,
      });
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

  private async loadSchemes(
    proverBytes: Uint8Array,
    verifierBytes: Uint8Array,
    provingModules?: { witnessBytes?: Uint8Array; derivativesBytes?: Uint8Array },
  ): Promise<{ prover: ProverScheme; verifier: VerifierScheme }> {
    if (!this.state.wasmReady || !this.provekit) {
      throw new Error("Proof runtime is not initialized yet.");
    }

    this.logs.log("Loading prover and verifier...");
    const loadStart = performance.now();

    const hasProvingModules = Boolean(provingModules?.witnessBytes || provingModules?.derivativesBytes);
    if (hasProvingModules && (!provingModules?.witnessBytes || !provingModules.derivativesBytes)) {
      throw new Error("Custom proving modules require both witness and derivatives WASM artifacts.");
    }

    const scheme = await this.provekit.loadArtifacts({
      prover: proverBytes,
      verifier: verifierBytes,
      witnessProvider: this.witnessProvider,
      provingModules: hasProvingModules
        ? {
            witness: provingModules!.witnessBytes!,
            derivatives: provingModules!.derivativesBytes!,
          }
        : undefined,
    });

    this.logs.log(`Scheme load time: ${(performance.now() - loadStart).toFixed(0)}ms`);
    return {
      prover: new SdkProverScheme(scheme),
      verifier: new SdkVerifierScheme(scheme),
    };
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
