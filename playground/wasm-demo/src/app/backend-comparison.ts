import type { ArtifactLoader } from "./artifact-loader.js";
import type { DemoDom } from "./dom.js";
import type { Proof, ProverScheme, VerifierScheme } from "./proof-types.js";
import type { AppState, BackendId, DiagnosticsWriter } from "./types.js";

type ComparisonStatus = "idle" | "running" | "success" | "unavailable" | "error";

interface ComparisonTarget {
  backend: BackendId;
  label: string;
  artifactId: string;
}

interface ComparisonResult {
  target: ComparisonTarget;
  status: ComparisonStatus;
  message: string;
  provingMs?: number;
  constraints?: number;
}

interface BackendComparisonDeps {
  dom: DemoDom;
  state: AppState;
  logs: DiagnosticsWriter;
  artifacts: ArtifactLoader;
  loadSchemes(
    proverBytes: Uint8Array,
    verifierBytes: Uint8Array,
    provingModules?: { witnessBytes?: Uint8Array; derivativesBytes?: Uint8Array },
  ): Promise<{ prover: ProverScheme; verifier: VerifierScheme }>;
  loadVerityV1Schemes(
    proverBytes: Uint8Array,
    verifierBytes: Uint8Array,
  ): Promise<{ prover: ProverScheme; verifier: VerifierScheme }>;
  waitForUi(): Promise<void>;
}

function formatMs(ms: number | undefined): string {
  return typeof ms === "number" ? `${(ms / 1000).toFixed(2)}s` : "-";
}

function formatCount(count: number | undefined): string {
  return typeof count === "number" ? count.toLocaleString() : "-";
}

function getMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function targetsFor(circuit: "passkey" | "webauthn"): ComparisonTarget[] {
  return [
    {
      backend: "mavros",
      label: "Mavros main",
      artifactId: `${circuit}-mavros`,
    },
    {
      backend: "verity-v1",
      label: "ProveKit v1 ACIR (Verity WASM)",
      artifactId: `${circuit}-v1`,
    },
  ];
}

export class BackendComparisonController {
  private results: ComparisonResult[] = [];

  constructor(private readonly deps: BackendComparisonDeps) {}

  bind(): void {
    this.deps.dom.compareButton.addEventListener("click", () => {
      void this.run();
    });
  }

  refresh(): void {
    const isBuiltIn = this.deps.state.activeCircuit === "passkey" || this.deps.state.activeCircuit === "webauthn";
    this.deps.dom.compareButton.disabled = !this.deps.state.wasmReady || !isBuiltIn;
  }

  reset(): void {
    if (this.deps.state.activeCircuit !== "passkey" && this.deps.state.activeCircuit !== "webauthn") {
      this.results = [];
      this.deps.dom.comparisonStatus.textContent = "Select Passkey or WebAuthn to compare backends.";
      this.render();
      this.refresh();
      return;
    }

    this.results = targetsFor(this.deps.state.activeCircuit).map((target) => ({
      target,
      status: "idle",
      message: "Waiting",
    }));
    this.deps.dom.comparisonStatus.textContent = `Ready to compare ${this.deps.state.activeCircuit}.`;
    this.render();
    this.refresh();
  }

  async run(): Promise<void> {
    if (!this.deps.state.wasmReady) {
      this.deps.logs.log("Proof runtime is not initialized yet.", "error");
      return;
    }
    if (this.deps.state.activeCircuit !== "passkey" && this.deps.state.activeCircuit !== "webauthn") {
      this.deps.logs.log("Backend comparison is only available for built-in circuits.", "warn");
      return;
    }

    const circuit = this.deps.state.activeCircuit;
    const targets = targetsFor(circuit);
    this.results = targets.map((target) => ({
      target,
      status: "idle",
      message: "Queued",
    }));
    this.deps.dom.compareButton.disabled = true;
    this.deps.dom.comparisonStatus.textContent = `Running ${circuit} backend comparison...`;
    this.render();

    for (const target of targets) {
      await this.runTarget(target);
      this.render();
    }

    this.deps.dom.comparisonStatus.textContent = `Comparison finished for ${circuit}.`;
    this.refresh();
  }

  private async runTarget(target: ComparisonTarget): Promise<void> {
    this.updateResult(target, { status: "running", message: "Running" });
    this.render();

    let prover: ProverScheme | null = null;
    let verifier: VerifierScheme | null = null;
    try {
      const status = await this.deps.artifacts.loadStatusById(target.artifactId);
      if (status && !status.available) {
        this.updateResult(target, {
          status: "unavailable",
          message: status.error ?? `${target.label} artifacts are unavailable.`,
        });
        return;
      }

      this.deps.logs.log(`[${target.label}] Loading artifacts...`);
      const { proverBytes, verifierBytes, witgenWasmBytes, adWasmBytes, metadata } =
        await this.deps.artifacts.loadArtifactsById(target.artifactId);
      ({ prover, verifier } = target.backend === "verity-v1"
        ? await this.deps.loadVerityV1Schemes(proverBytes, verifierBytes)
        : await this.deps.loadSchemes(proverBytes, verifierBytes, {
            witnessBytes: witgenWasmBytes,
            derivativesBytes: adWasmBytes,
          }));

      const inputs = await this.deps.artifacts.loadInputsById(target.artifactId);
      await this.deps.waitForUi();
      const started = performance.now();
      const proof = await prover.prove(inputs);
      const provingMs = performance.now() - started;
      await this.verifyProof(target, verifier, proof);

      this.updateResult(target, {
        status: "success",
        message: "Verified",
        provingMs,
        constraints: metadata?.constraints,
      });
    } catch (error) {
      this.updateResult(target, {
        status: "error",
        message: getMessage(error),
      });
    } finally {
      prover?.dispose();
      verifier?.dispose();
    }
  }

  private async verifyProof(target: ComparisonTarget, verifier: VerifierScheme, proof: Proof): Promise<void> {
    const verified = await verifier.verify(proof);
    if (!verified) {
      throw new Error(`${target.label} verifier rejected the proof`);
    }
  }

  private updateResult(target: ComparisonTarget, patch: Partial<Omit<ComparisonResult, "target">>): void {
    this.results = this.results.map((result) => {
      if (result.target.artifactId !== target.artifactId) {
        return result;
      }
      return { ...result, ...patch };
    });
  }

  private render(): void {
    const v1 = this.results.find((result) => result.target.backend === "verity-v1" && result.status === "success");
    const mavros = this.results.find((result) => result.target.backend === "mavros" && result.status === "success");

    this.deps.dom.comparisonBody.innerHTML = this.results.map((result) => {
      const timeDelta = result === mavros && v1?.provingMs && result.provingMs
        ? `${((result.provingMs - v1.provingMs) / 1000).toFixed(2)}s`
        : result === v1
          ? "baseline"
          : "-";
      const constraintDelta = result === mavros && typeof v1?.constraints === "number" && typeof result.constraints === "number"
        ? (result.constraints - v1.constraints).toLocaleString()
        : result === v1
          ? "baseline"
          : "-";

      return `
        <tr class="comparison-row comparison-${result.status}">
          <td>${escapeHtml(result.target.label)}</td>
          <td>${escapeHtml(result.message)}</td>
          <td>${formatMs(result.provingMs)}</td>
          <td>${formatCount(result.constraints)}</td>
          <td>${timeDelta}</td>
          <td>${constraintDelta}</td>
        </tr>
      `;
    }).join("");
  }
}
