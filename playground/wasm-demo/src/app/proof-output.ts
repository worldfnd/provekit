import type { Proof } from "@atheonxyz/verity";

import type { CircuitMetadata, LogWriter } from "./types.js";

interface ProofOutputDom {
  totalTime: HTMLElement;
  proofSize: HTMLElement;
  constraints: HTMLElement;
  witnesses: HTMLElement;
  proofOutput: HTMLElement;
  proofCard: HTMLElement;
}

function decodePublicInputs(proofText: string): bigint[] | null {
  const parsed = JSON.parse(proofText) as { public_inputs?: string[] };
  if (!parsed.public_inputs?.length) {
    return null;
  }

  return parsed.public_inputs.map((hex) => {
    const bytes = hex.match(/.{2}/g);
    if (!bytes) {
      throw new Error("Invalid public input encoding");
    }
    return BigInt(`0x${bytes.reverse().join("")}`);
  });
}

export class ProofOutputPresenter {
  constructor(
    private readonly dom: ProofOutputDom,
    private readonly logs: LogWriter,
  ) {}

  reset(): void {
    this.dom.totalTime.textContent = "-";
    this.dom.proofSize.textContent = "-";
    this.dom.constraints.textContent = "-";
    this.dom.witnesses.textContent = "-";
    this.dom.proofOutput.textContent = "";
    this.dom.proofCard.style.display = "none";
  }

  updateMetrics(metadata: CircuitMetadata | null, proofSize: number, totalTimeMs: number): void {
    this.dom.totalTime.textContent = `${(totalTimeMs / 1000).toFixed(2)}s`;
    this.dom.proofSize.textContent = `${(proofSize / 1024).toFixed(1)} KB`;
    this.dom.constraints.textContent = typeof metadata?.constraints === "number" ? metadata.constraints.toLocaleString() : "—";
    this.dom.witnesses.textContent = typeof metadata?.witnesses === "number" ? metadata.witnesses.toLocaleString() : "—";
  }

  renderProof(proof: Proof): void {
    const proofText = new TextDecoder().decode(proof.data);
    this.dom.proofOutput.textContent = proofText.length > 2000 ? `${proofText.slice(0, 2000)}...` : proofText;
    this.dom.proofCard.style.display = "block";

    try {
      const values = decodePublicInputs(proofText);
      if (!values?.length) {
        return;
      }

      if (values.every((value) => value < 256n)) {
        const hexString = values.map((value) => value.toString(16).padStart(2, "0")).join("");
        this.logs.log(`Public inputs (${values.length}): 0x${hexString}`);
        return;
      }

      this.logs.log(`Public inputs (${values.length}):`);
      values.forEach((value, index) => {
        this.logs.log(`  [${index}]: 0x${value.toString(16)}`);
      });
    } catch {
      // Proof preview is best-effort only.
    }
  }
}
