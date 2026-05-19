import type { ChecklistElements } from "./dom.js";
import type { UploadKey } from "./upload-rules.js";

export const DEFAULT_CHECKLIST_LABELS: Record<UploadKey, string> = {
  prover: "prover.pkp",
  verifier: "verifier.pkv",
  inputs: "inputs.json / Prover.toml",
  witgenWasm: "witgen.wasm (Mavros)",
  adWasm: "ad.wasm (Mavros)",
};

const CHECK_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>`;

function formatFileSize(size: number): string {
  return size > 1024 * 1024
    ? `${(size / 1024 / 1024).toFixed(1)} MB`
    : `${(size / 1024).toFixed(1)} KB`;
}

export class ChecklistPresenter {
  constructor(private readonly checklist: Record<UploadKey, ChecklistElements>) {}

  reset(): void {
    for (const [key, label] of Object.entries(DEFAULT_CHECKLIST_LABELS) as [UploadKey, string][]) {
      const item = this.checklist[key];
      item.root.className = "checklist-item pending";
      item.icon.textContent = "-";
      item.name.textContent = label;
      item.right.textContent = "Waiting...";
      item.right.style.fontStyle = "italic";
    }
  }

  markUploaded(key: UploadKey, file: File): void {
    const item = this.checklist[key];
    item.root.className = "checklist-item verified";
    item.icon.innerHTML = CHECK_ICON;
    item.name.textContent = file.name;
    item.right.style.fontStyle = "normal";
    item.right.textContent = formatFileSize(file.size);
  }
}
