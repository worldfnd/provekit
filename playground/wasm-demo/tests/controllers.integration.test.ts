import { beforeEach, describe, expect, it, vi } from "vitest";

import { ChecklistPresenter } from "../src/app/checklist.js";
import { CircuitController } from "../src/app/circuit-controller.js";
import { collectDom } from "../src/app/dom.js";
import { ProofOutputPresenter } from "../src/app/proof-output.js";
import type { Proof, VerifierScheme } from "../src/app/proof-types.js";
import { StepPresenter } from "../src/app/steps.js";
import type { AppState, CircuitName, LogType } from "../src/app/types.js";
import { VerifyController } from "../src/app/verify-controller.js";

function renderFixture(): void {
  document.body.innerHTML = `
    <div id="logContainer"></div>
    <button id="runBtn" disabled></button>
    <button id="verifyBtn" disabled></button>
    <div id="totalTimeUi">-</div>
    <div id="proofSizeUi">-</div>
    <div id="constraintsUi">-</div>
    <div id="witnessesUi">-</div>
    <div id="proofOutput"></div>
    <div id="proofCard" style="display:none"></div>
    <div id="customConfigPanel" style="display:none"></div>
    <h2 id="stepsTitle"></h2>
    <p id="circuitDescription"></p>
    <div id="dropzone"></div>
    <input id="fileInput" />
    <button id="btnSelectFiles"></button>
    <svg id="copyLogBtn" stroke="#555"></svg>
    <button id="compareBtn" disabled></button>
    <div id="comparisonStatus"></div>
    <table><tbody id="comparisonBody"></tbody></table>
    <button class="circuit-btn active" data-circuit="passkey"></button>
    <button class="circuit-btn" data-circuit="webauthn"></button>
    ${[1, 2, 3, 4, 5].map((step) => `
      <div id="step${step}-container" class="step-item">
        <div id="step${step}-icon" class="step-icon">${step}</div>
        <div class="step-name">Step ${step}</div>
        <div id="step${step}-status" class="step-status">Waiting...</div>
      </div>
    `).join("")}
    ${["prover", "verifier", "inputs", "witgenWasm", "adWasm"].map((key) => `
      <div id="check-${key}" class="checklist-item pending">
        <div class="item-icon">-</div>
        <span class="item-name">${key}</span>
        <div class="item-right">Waiting...</div>
      </div>
    `).join("")}
  `;
}

function createState(activeCircuit: CircuitName = "passkey"): AppState {
  return {
    activeCircuit,
    customFiles: {},
    wasmReady: true,
    lastProof: null,
    activeVerifier: null,
  };
}

function createLogs() {
  const entries: Array<{ message: string; type?: LogType }> = [];
  return {
    entries,
    log(message: string, type?: LogType) {
      entries.push({ message, type });
    },
    logCircuitSelection(labelHtml: string, message: string) {
      entries.push({ message: `${labelHtml} ${message}` });
    },
  };
}

function setupCircuitHarness(activeCircuit: CircuitName = "passkey") {
  renderFixture();
  const dom = collectDom(document);
  const logs = createLogs();
  const steps = new StepPresenter(dom.steps);
  const checklist = new ChecklistPresenter(dom.checklist);
  const proofOutput = new ProofOutputPresenter(dom, logs);
  const state = createState(activeCircuit);
  const controller = new CircuitController({
    dom,
    state,
    logs,
    steps,
    checklist,
    proofOutput,
    disposeActiveVerifier: () => {
      state.activeVerifier = null;
    },
  });

  return { controller, dom, logs, state };
}

beforeEach(() => {
  renderFixture();
});

describe("CircuitController", () => {
  it("resets proof UI and custom state when switching circuits", () => {
    const { controller, dom, state } = setupCircuitHarness("custom");
    state.customFiles = {
      prover: new File(["a"], "prover.pkp"),
      verifier: new File(["b"], "verifier.pkv"),
      inputs: new File(["{}"], "inputs.json"),
    };
    state.lastProof = {} as Proof;
    dom.verifyButton.disabled = false;
    dom.proofCard.style.display = "block";

    controller.applyCircuit("webauthn", false);

    expect(state.activeCircuit).toBe("webauthn");
    expect(state.customFiles).toEqual({});
    expect(dom.verifyButton.disabled).toBe(true);
    expect(dom.proofCard.style.display).toBe("none");
    expect(dom.steps[0].status.textContent).toBe("Waiting...");
  });

  it("treats passkey as a built-in P-256 circuit ready to run after runtime load", () => {
    const { controller, dom, state } = setupCircuitHarness("webauthn");

    controller.applyCircuit("passkey", false);

    expect(state.activeCircuit).toBe("passkey");
    expect(dom.customConfigPanel.style.display).toBe("none");
    expect(dom.runButton.disabled).toBe(false);
    expect(dom.circuitDescription.textContent).toContain("P-256 passkey signature");
    expect(dom.stepsTitle.textContent).toBe("PROOF GENERATION STEPS [PASSKEY]");
  });

  it("unlocks custom proving only after all required files are uploaded", () => {
    const { controller, dom, state } = setupCircuitHarness("passkey");
    controller.bind();
    controller.applyCircuit("custom", false);

    const dropEvent = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(dropEvent, "dataTransfer", {
      value: {
        files: [
          new File(["pkp"], "prover.pkp"),
          new File(["pkv"], "verifier.pkv"),
          new File(["toml"], "Prover.toml"),
        ],
      },
    });

    dom.dropzone.dispatchEvent(dropEvent);

    expect(state.customFiles.prover?.name).toBe("prover.pkp");
    expect(state.customFiles.verifier?.name).toBe("verifier.pkv");
    expect(state.customFiles.inputs?.name).toBe("Prover.toml");
    expect(dom.runButton.disabled).toBe(false);
  });

  it("requires confirmation before accepting custom Mavros WASM artifacts", () => {
    const confirmSpy = vi.spyOn(globalThis, "confirm").mockReturnValue(false);
    const { controller, dom, logs, state } = setupCircuitHarness("passkey");
    controller.bind();
    controller.applyCircuit("custom", false);

    const dropEvent = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(dropEvent, "dataTransfer", {
      value: {
        files: [
          new File(["witgen"], "witgen.wasm"),
          new File(["ad"], "ad.wasm"),
        ],
      },
    });

    dom.dropzone.dispatchEvent(dropEvent);

    expect(confirmSpy).toHaveBeenCalledOnce();
    expect(state.customFiles.witgenWasm).toBeUndefined();
    expect(state.customFiles.adWasm).toBeUndefined();
    expect(logs.entries.some(({ message }) => message.includes("Skipped uploaded Mavros WASM")))
      .toBe(true);

    confirmSpy.mockRestore();
  });
});

describe("VerifyController", () => {
  it("renders invalid proofs as an explicit error state", async () => {
    renderFixture();
    const dom = collectDom(document);
    const logs = createLogs();
    const steps = new StepPresenter(dom.steps);
    const state = createState();
    state.lastProof = {} as Proof;
    state.activeVerifier = {
      verify: async () => false,
      serialize: async () => new Uint8Array(),
      dispose() {},
    } satisfies VerifierScheme;

    const controller = new VerifyController({
      dom,
      state,
      logs,
      steps,
      waitForUi: async () => {},
    });

    await controller.verify();

    // Button stays disabled — re-verifying the same proof is a no-op.
    expect(dom.verifyButton.disabled).toBe(true);
    expect(dom.steps[4].status.textContent).toContain("Invalid");
    expect(dom.steps[4].status.className).toContain("error-text");
    expect(dom.steps[4].container.className).toContain("error");
  });
});
