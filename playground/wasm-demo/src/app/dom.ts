import type { UploadKey } from "./upload-rules.js";

export interface StepElements {
  readonly stepNumber: number;
  readonly container: HTMLElement;
  readonly icon: HTMLElement;
  readonly name: HTMLElement;
  readonly status: HTMLElement;
}

export interface ChecklistElements {
  readonly root: HTMLElement;
  readonly icon: HTMLElement;
  readonly name: HTMLElement;
  readonly right: HTMLElement;
}

export interface DemoDom {
  readonly logContainer: HTMLElement;
  readonly runButton: HTMLButtonElement;
  readonly verifyButton: HTMLButtonElement;
  readonly totalTime: HTMLElement;
  readonly proofSize: HTMLElement;
  readonly constraints: HTMLElement;
  readonly witnesses: HTMLElement;
  readonly proofOutput: HTMLElement;
  readonly proofCard: HTMLElement;
  readonly customConfigPanel: HTMLElement;
  readonly stepsTitle: HTMLElement;
  readonly circuitDescription: HTMLElement;
  readonly dropzone: HTMLElement;
  readonly fileInput: HTMLInputElement;
  readonly selectFilesButton: HTMLButtonElement;
  readonly copyLogsButton: HTMLElement;
  readonly circuitButtons: HTMLButtonElement[];
  readonly steps: StepElements[];
  readonly checklist: Record<UploadKey, ChecklistElements>;
}

function requireElement<T extends HTMLElement>(document: Document, id: string): T {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Missing required element: ${id}`);
  }
  return element as T;
}

function collectStep(document: Document, stepNumber: number): StepElements {
  const container = requireElement<HTMLElement>(document, `step${stepNumber}-container`);
  const name = container.querySelector<HTMLElement>(".step-name");
  if (!name) {
    throw new Error(`Missing step name for step ${stepNumber}`);
  }

  return {
    stepNumber,
    container,
    icon: requireElement<HTMLElement>(document, `step${stepNumber}-icon`),
    name,
    status: requireElement<HTMLElement>(document, `step${stepNumber}-status`),
  };
}

function collectChecklist(document: Document, key: UploadKey): ChecklistElements {
  const root = requireElement<HTMLElement>(document, `check-${key}`);
  const icon = root.querySelector<HTMLElement>(".item-icon");
  const name = root.querySelector<HTMLElement>(".item-name");
  const right = root.querySelector<HTMLElement>(".item-right");

  if (!icon || !name || !right) {
    throw new Error(`Checklist item is incomplete for ${key}`);
  }

  return { root, icon, name, right };
}

export function collectDom(document: Document): DemoDom {
  return {
    logContainer: requireElement(document, "logContainer"),
    runButton: requireElement(document, "runBtn"),
    verifyButton: requireElement(document, "verifyBtn"),
    totalTime: requireElement(document, "totalTimeUi"),
    proofSize: requireElement(document, "proofSizeUi"),
    constraints: requireElement(document, "constraintsUi"),
    witnesses: requireElement(document, "witnessesUi"),
    proofOutput: requireElement(document, "proofOutput"),
    proofCard: requireElement(document, "proofCard"),
    customConfigPanel: requireElement(document, "customConfigPanel"),
    stepsTitle: requireElement(document, "stepsTitle"),
    circuitDescription: requireElement(document, "circuitDescription"),
    dropzone: requireElement(document, "dropzone"),
    fileInput: requireElement(document, "fileInput"),
    selectFilesButton: requireElement(document, "btnSelectFiles"),
    copyLogsButton: requireElement(document, "copyLogBtn"),
    circuitButtons: Array.from(document.querySelectorAll<HTMLButtonElement>(".circuit-btn")),
    steps: [1, 2, 3, 4, 5].map((stepNumber) => collectStep(document, stepNumber)),
    checklist: {
      prover: collectChecklist(document, "prover"),
      verifier: collectChecklist(document, "verifier"),
      inputs: collectChecklist(document, "inputs"),
    },
  };
}
