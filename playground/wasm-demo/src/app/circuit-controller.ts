import type { DemoDom } from "./dom.js";
import type { LogWriter, AppState, CircuitName } from "./types.js";
import { ChecklistPresenter } from "./checklist.js";
import { ProofOutputPresenter } from "./proof-output.js";
import { StepPresenter } from "./steps.js";
import { classifyUpload, isCustomReady } from "./upload-rules.js";

const CIRCUIT_DESCRIPTIONS: Record<CircuitName, string> = {
  sha256: "17 chained SHA-256 rounds over a 32-byte state.",
  poseidon: "Poseidon2 permutation × 1,000 rounds over 4 field elements.",
  custom: "Upload your own Noir circuit artifacts to benchmark proof generation and verification.",
};

function circuitLabel(circuit: CircuitName): string {
  return circuit === "custom"
    ? `<span style="color:var(--accent-cyan)">[Custom]</span>`
    : `<span style="color:var(--accent-cyan)">[${circuit.toUpperCase()}]</span>`;
}

function circuitMessage(circuit: CircuitName): string {
  return circuit === "custom"
    ? "Awaiting circuit artifact uploads..."
    : "Initializing environment...";
}

interface CircuitControllerDeps {
  dom: DemoDom;
  state: AppState;
  logs: LogWriter & { logCircuitSelection(labelHtml: string, message: string): void };
  steps: StepPresenter;
  checklist: ChecklistPresenter;
  proofOutput: ProofOutputPresenter;
  disposeActiveVerifier(): void;
}

export class CircuitController {
  private acceptedCustomMavrosWasmRisk = false;

  constructor(private readonly deps: CircuitControllerDeps) {}

  bind(): void {
    const { dom } = this.deps;

    for (const button of dom.circuitButtons) {
      button.addEventListener("click", () => {
        const circuit = button.dataset.circuit as CircuitName | undefined;
        if (circuit) {
          this.applyCircuit(circuit, true);
        }
      });
    }

    dom.selectFilesButton.addEventListener("click", (event) => {
      event.stopPropagation();
      dom.fileInput.click();
    });

    dom.fileInput.addEventListener("change", () => {
      const files = dom.fileInput.files;
      if (files?.length) {
        this.handleUploadedFiles(Array.from(files));
      }
      dom.fileInput.value = "";
    });

    dom.dropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      dom.dropzone.style.borderColor = "var(--accent-cyan)";
      dom.dropzone.style.background = "rgba(0, 229, 255, 0.05)";
    });

    dom.dropzone.addEventListener("dragleave", () => {
      dom.dropzone.style.borderColor = "";
      dom.dropzone.style.background = "";
    });

    dom.dropzone.addEventListener("drop", (event) => {
      event.preventDefault();
      dom.dropzone.style.borderColor = "";
      dom.dropzone.style.background = "";
      const files = event.dataTransfer?.files;
      if (files?.length) {
        this.handleUploadedFiles(Array.from(files));
      }
    });
  }

  applyCircuit(circuit: CircuitName, announceSelection: boolean): void {
    const { dom, logs, proofOutput, state, steps } = this.deps;
    state.activeCircuit = circuit;

    for (const button of dom.circuitButtons) {
      button.classList.toggle("active", button.dataset.circuit === circuit);
    }

    if (announceSelection) {
      logs.logCircuitSelection(circuitLabel(circuit), circuitMessage(circuit));
    }

    dom.circuitDescription.textContent = CIRCUIT_DESCRIPTIONS[circuit];
    dom.stepsTitle.textContent = `PROOF GENERATION STEPS [${circuit.toUpperCase()}]`;
    dom.customConfigPanel.style.display = circuit === "custom" ? "grid" : "none";

    // Step 1 reflects the long-lived runtime load, so only reset steps 2-5
    // when switching circuits.
    steps.reset(2);
    proofOutput.reset();
    state.lastProof = null;
    dom.verifyButton.disabled = true;
    this.deps.disposeActiveVerifier();

    if (circuit === "custom") {
      this.resetCustomState();
    } else {
      state.customFiles = {};
      this.acceptedCustomMavrosWasmRisk = false;
    }

    this.refreshRunButton();
  }

  refreshRunButton(): void {
    const { dom, state } = this.deps;
    dom.runButton.disabled = state.activeCircuit === "custom"
      ? !isCustomReady(state.customFiles, state.wasmReady)
      : !state.wasmReady;
  }

  private resetCustomState(): void {
    this.deps.state.customFiles = {};
    this.acceptedCustomMavrosWasmRisk = false;
    this.deps.checklist.reset();
  }

  private handleUploadedFiles(files: File[]): void {
    const { logs, checklist, state } = this.deps;
    const classified = files.map((file) => ({ file, key: classifyUpload(file.name) }));
    const hasMavrosWasm = classified.some(({ key }) => key === "witgenWasm" || key === "adWasm");
    let allowMavrosWasm = this.acceptedCustomMavrosWasmRisk;

    if (hasMavrosWasm && !allowMavrosWasm) {
      allowMavrosWasm = globalThis.confirm(
        "Uploaded Mavros witgen/ad WASM modules will be executed in this page while proving. Only continue with artifacts you trust."
      );
      this.acceptedCustomMavrosWasmRisk = allowMavrosWasm;
      if (!allowMavrosWasm) {
        logs.log("Skipped uploaded Mavros WASM artifacts", "warn");
      }
    }

    for (const { file, key } of classified) {
      logs.log(`File uploaded: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
      if (!key) {
        logs.log(`Unrecognized file: ${file.name}`, "error");
        continue;
      }
      if ((key === "witgenWasm" || key === "adWasm") && !allowMavrosWasm) {
        continue;
      }

      state.customFiles[key] = file;
      checklist.markUploaded(key, file);
    }

    if (isCustomReady(state.customFiles, state.wasmReady)) {
      logs.log("All required files uploaded — ready to generate proof", "success");
    }

    this.refreshRunButton();
  }
}
