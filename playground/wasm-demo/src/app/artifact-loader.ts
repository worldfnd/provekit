import { parseSimpleToml } from "../../shared/toml-parser.mjs";

import type { CircuitMetadata, CircuitName, CustomFiles, DiagnosticsWriter } from "./types.js";

export interface ArtifactBundle {
  proverBytes: Uint8Array;
  verifierBytes: Uint8Array;
  metadata: CircuitMetadata | null;
}

async function loadMetadata(base: string): Promise<CircuitMetadata | null> {
  try {
    const response = await fetch(`${base}metadata.json`);
    if (!response.ok) {
      return null;
    }
    return (await response.json()) as CircuitMetadata;
  } catch {
    return null;
  }
}

async function loadInputsJson(base: string): Promise<Record<string, unknown>> {
  const response = await fetch(`${base}inputs.json`);
  if (!response.ok) {
    throw new Error("inputs.json not found. Run setup first.");
  }
  return (await response.json()) as Record<string, unknown>;
}

function logBinarySize(logs: DiagnosticsWriter, label: string, bytes: Uint8Array): void {
  logs.log(`${label}: ${(bytes.byteLength / 1024 / 1024).toFixed(2)} MB`);
}

export class ArtifactLoader {
  constructor(
    private readonly logs: DiagnosticsWriter,
    private readonly readCircuitStats: (proverBytes: Uint8Array) => Promise<{ constraints: number; witnesses: number }>,
  ) {}

  async loadArtifacts(circuit: CircuitName, customFiles: CustomFiles): Promise<ArtifactBundle> {
    const bundle = circuit === "custom"
      ? await this.loadCustomArtifacts(customFiles)
      : await this.loadBuiltInArtifacts(circuit);

    logBinarySize(this.logs, "Prover artifact", bundle.proverBytes);
    logBinarySize(this.logs, "Verifier artifact", bundle.verifierBytes);
    this.logs.logMemory("After loading artifacts", {
      proverBytes: bundle.proverBytes,
      verifierBytes: bundle.verifierBytes,
    });

    const stats = await this.readCircuitStats(bundle.proverBytes);
    this.logs.log(`Circuit: ${stats.constraints.toLocaleString()} constraints, ${stats.witnesses.toLocaleString()} witnesses`);

    return {
      ...bundle,
      metadata: { ...bundle.metadata, ...stats },
    };
  }

  async loadInputs(circuit: CircuitName, customFiles: CustomFiles): Promise<Record<string, unknown>> {
    if (circuit !== "custom") {
      this.logs.log("Loading inputs...");
      return loadInputsJson(`artifacts/${circuit}/`);
    }

    const inputsFile = customFiles.inputs;
    if (!inputsFile) {
      throw new Error("Upload inputs.json or Prover.toml before running the custom circuit.");
    }

    if (inputsFile.name.toLowerCase().endsWith(".toml")) {
      this.logs.log("Parsing Prover.toml...");
      return parseSimpleToml(await inputsFile.text()) as Record<string, unknown>;
    }

    return JSON.parse(await inputsFile.text()) as Record<string, unknown>;
  }

  private async loadBuiltInArtifacts(circuit: Exclude<CircuitName, "custom">): Promise<ArtifactBundle> {
    const base = `artifacts/${circuit}/`;
    const metadata = await loadMetadata(base);

    this.logs.log(`Circuit: ${metadata?.name ?? "unknown"}`);
    this.logs.log("Loading prover (.pkp) and verifier (.pkv) artifacts...");
    this.logs.logMemory("Before loading artifacts");

    const [proverResponse, verifierResponse] = await Promise.all([
      fetch(`${base}prover.pkp`),
      fetch(`${base}verifier.pkv`),
    ]);

    if (!proverResponse.ok || !verifierResponse.ok) {
      throw new Error("Missing prover or verifier artifact. Run setup first.");
    }

    return {
      proverBytes: new Uint8Array(await proverResponse.arrayBuffer()),
      verifierBytes: new Uint8Array(await verifierResponse.arrayBuffer()),
      metadata,
    };
  }

  private async loadCustomArtifacts(customFiles: CustomFiles): Promise<ArtifactBundle> {
    const { prover, verifier } = customFiles;
    if (!prover || !verifier) {
      throw new Error("Upload prover and verifier artifacts before running the custom circuit.");
    }

    this.logs.log("Loading uploaded prover and verifier artifacts...");
    this.logs.logMemory("Before loading artifacts");

    return {
      proverBytes: new Uint8Array(await prover.arrayBuffer()),
      verifierBytes: new Uint8Array(await verifier.arrayBuffer()),
      metadata: null,
    };
  }
}
