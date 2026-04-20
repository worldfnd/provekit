import { deriveStepVisualState, type StepStateKind } from "./status-visuals.js";
import type { StepElements } from "./dom.js";

export interface StepStatus {
  kind: StepStateKind;
  text: string;
}

export const stepStatus = {
  idle: (text = "Waiting..."): StepStatus => ({ kind: "idle", text }),
  running: (text: string): StepStatus => ({ kind: "running", text }),
  success: (text: string): StepStatus => ({ kind: "success", text }),
  error: (text: string): StepStatus => ({ kind: "error", text }),
};

const CHECK_ICON = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
const CROSS_ICON = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
const SPINNER_ICON = `<svg class="spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>`;

export class StepPresenter {
  private readonly stepMap: Map<number, StepElements>;

  constructor(steps: StepElements[]) {
    this.stepMap = new Map(steps.map((step) => [step.stepNumber, step]));
  }

  /** Reset steps with number >= `startAt` to their idle state. */
  reset(startAt = 1): void {
    for (const stepNumber of this.stepMap.keys()) {
      if (stepNumber >= startAt) {
        this.setStatus(stepNumber, stepStatus.idle());
      }
    }
  }

  setStatus(stepNumber: number, status: StepStatus): void {
    const step = this.stepMap.get(stepNumber);
    if (!step) {
      throw new Error(`Unknown step: ${stepNumber}`);
    }

    step.status.textContent = status.text;

    const visual = deriveStepVisualState(status.kind);
    step.container.className = visual.containerClassName;
    step.icon.className = visual.iconClassName;
    step.status.className = visual.statusClassName;

    switch (visual.iconKind) {
      case "spinner":
        step.icon.innerHTML = SPINNER_ICON;
        break;
      case "check":
        step.icon.innerHTML = CHECK_ICON;
        break;
      case "cross":
        step.icon.innerHTML = CROSS_ICON;
        break;
      case "number":
        step.icon.textContent = String(step.stepNumber);
        break;
    }
  }
}
