export type StepStateKind = "idle" | "running" | "success" | "error";
export type StepIconKind = "spinner" | "check" | "cross" | "number";

export interface StepVisualState {
  containerClassName: string;
  iconClassName: string;
  iconKind: StepIconKind;
  statusClassName: string;
}

export function deriveStepVisualState(kind: StepStateKind): StepVisualState {
  switch (kind) {
    case "running":
      return {
        containerClassName: "step-item active",
        iconClassName: "step-icon active",
        iconKind: "spinner",
        statusClassName: "step-status",
      };
    case "success":
      return {
        containerClassName: "step-item success",
        iconClassName: "step-icon success",
        iconKind: "check",
        statusClassName: "step-status success-text",
      };
    case "error":
      return {
        containerClassName: "step-item error",
        iconClassName: "step-icon error",
        iconKind: "cross",
        statusClassName: "step-status error-text",
      };
    case "idle":
      return {
        containerClassName: "step-item",
        iconClassName: "step-icon",
        iconKind: "number",
        statusClassName: "step-status",
      };
  }
}
