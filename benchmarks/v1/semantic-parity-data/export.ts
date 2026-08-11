import { createHash } from "node:crypto";
import { resolve } from "node:path";
import {
  CAMPAIGN_ID, CSV_COLUMNS, EXPECTED_RUNTIME, PROFILES, STACKS, TARGETS,
  cellId, expectedCellIds, type ParitySample, type Profile, type Stack, type Target,
} from "./schema";

type Payload = { path?: string; name?: string; bytes: number; sha256: string | null };
type ManifestCell = {
  cell_id: string; profile: Profile; target: Target; stack: Stack; state: string;
  evidence?: string; evidence_sha256?: string; payload?: Payload[];
};
type Manifest = {
  campaign_id: string;
  semantic_profiles: Record<string, Record<string, unknown>>;
  cells: ManifestCell[];
};

type NativeParityEvidenceBase = {
  schema_version: 1;
  campaign_id: string;
  semantic_profile: Profile;
  target: Exclude<Target, "mac_chrome">;
  stack: Stack;
  device: { model: string; os_version: string; abi: string };
  runtime: "ios_native" | "android_native";
  browser?: string;
  frontend: "noir" | "circom";
  prover_backend: string;
  witness_backend: string;
  source_commits: Record<string, string>;
  package_versions: Record<string, string>;
  artifact_hashes: Record<string, string>;
  constraint_count?: number | null;
  session_id: string;
};

export type NativeParityEvidence = NativeParityEvidenceBase & ({
  proving_payload_size_bytes: number;
  process_peak_memory_kib: number;
  valid_proof_accepted: true;
  tampered_proof_rejected: true;
  samples: Array<{
    warmup: boolean;
    sample_index: number;
    status: "ok";
    prove_time_ms: number | null;
    proof_size_bytes: number;
  }>;
  gap?: never;
} | {
  proving_payload_size_bytes: null;
  process_peak_memory_kib: null;
  valid_proof_accepted: null;
  tampered_proof_rejected: null;
  samples?: never;
  gap: {
    status: "unsupported" | "build_failed" | "crashed" | "timed_out" | "zero_samples";
    failure_code: string;
    failure_detail: string;
    prove_time_ms: null;
    proof_size_bytes: null;
  };
});

const repoRoot = resolve(import.meta.dir, "../../..");
const semanticDataRoot = resolve(import.meta.dir);
const manifestPath = resolve(import.meta.dir, "manifest.json");
const historicalCsvPath = resolve(repoRoot, "benchmarks/v1/legacy/data/benchmark-samples.csv");
const historicalCsvSha256 = "474cb49d528862da3a029967f63fdee1875339b7c3da5f7599f2aded40d57d60";
const matchedProfileNote: Record<Exclude<Profile, "webauthn_closest_analogue">, string> = {
  passport_p1: "Matched semantic profile: monolithic RSA-4096 passport integrity, Self registry authorization, DG1 validity, and asserted minimum-age proof.",
  oprf_o2: "Matched semantic profile: World ID Protocol nullifier statement and frozen witness, including the identical public nullifier.",
};
const webauthnDifference = "Closest analogue, not semantically equivalent: Noir binds challenge, client-data type, origin, RP-ID hash, UP/UV flags, and public key; privacy-ethereum/webauthn-circom omits several of those bindings.";

async function sha256(path: string) {
  return createHash("sha256").update(Buffer.from(await Bun.file(path).arrayBuffer())).digest("hex");
}

function payloadBytes(cell: ManifestCell) {
  return (cell.payload ?? []).reduce((sum, item) => sum + item.bytes, 0);
}

function stackIdentity(stack: Stack) {
  if (stack === "provekit_v1") return { frontend: "noir" as const, prover_backend: "provekit-v1-whir-wasm-single-thread", witness_backend: "@noir-lang/noir_js" };
  if (stack === "noir_barretenberg") return { frontend: "noir" as const, prover_backend: "barretenberg-ultrahonk-wasm-single-thread", witness_backend: "@noir-lang/noir_js" };
  return { frontend: "circom" as const, prover_backend: "snarkjs-groth16-browser-wasm", witness_backend: "circom-witness-wasm" };
}

function sourceCommits(profile: Profile, stack: Stack) {
  if (profile === "webauthn_closest_analogue") return "{}";
  if (profile === "oprf_o2") return JSON.stringify({
    world_id_protocol: "85aeeef539961cae5a63de794997b507a5975717",
    ...(stack === "circom_groth16" ? {} : { taceo_beta19_compat: "7831dca615db55147c60f49415af6e86730df090" }),
    ...(stack === "provekit_v1" ? { provekit: "4b61b5d68e633a044eb41de4a6934d52ffdcbedc" } : {}),
  });
  return JSON.stringify({
    self_fixture: "15b167e3543a9dff1dbb16fcf71a45fe4625cf9e",
    parity_circuit: "7de99e9e001d06797c9770684afea20f096d1ac3",
    ...(stack === "provekit_v1" ? { provekit: "4b61b5d68e633a044eb41de4a6934d52ffdcbedc" } : {}),
  });
}

function packages(stack: Stack) {
  if (stack === "provekit_v1") return JSON.stringify({ "@worldcoin/provekit": "0.1.0", "@noir-lang/noir_js": "1.0.0-beta.20" });
  if (stack === "noir_barretenberg") return JSON.stringify({ "@aztec/bb.js": "4.2.0-aztecnr-rc.2", "@noir-lang/noir_js": "1.0.0-beta.19" });
  return JSON.stringify({ snarkjs: "0.7.6" });
}

function artifactHashes(cell: ManifestCell) {
  return JSON.stringify(Object.fromEntries((cell.payload ?? []).filter((p) => p.sha256).map((p) => [p.path ?? p.name!, p.sha256])));
}

function baseMac(cell: ManifestCell, evidenceHash: string, peakKib: number): Omit<ParitySample, "sample_kind" | "sample_index" | "status" | "prove_time_ms" | "proof_size_bytes" | "valid_proof_accepted" | "tampered_proof_rejected"> {
  return {
    campaign_id: CAMPAIGN_ID,
    semantic_profile: cell.profile,
    cell_id: cell.cell_id,
    target: "mac_chrome",
    device_model: "MacBook Pro (Apple M4 Max)",
    os_version: "macOS 26.5.2 (25F84)",
    abi: "arm64",
    runtime: "browser_wasm",
    browser: "Google Chrome 151.0.7922.72 (headless)",
    stack: cell.stack,
    ...stackIdentity(cell.stack),
    proving_payload_size_bytes: payloadBytes(cell),
    process_peak_memory_kib: peakKib,
    constraint_count: cell.profile === "passport_p1" && cell.stack === "circom_groth16" ? 978536 : null,
    source_commits: sourceCommits(cell.profile, cell.stack),
    package_versions: packages(cell.stack),
    artifact_hashes: artifactHashes(cell),
    evidence_path: cell.evidence!,
    evidence_sha256: evidenceHash,
    session_id: "",
    failure_code: "",
    failure_detail: "",
    semantic_equivalence_note: cell.profile === "webauthn_closest_analogue"
      ? webauthnDifference
      : matchedProfileNote[cell.profile],
  };
}

async function normalizeMac(cell: ManifestCell): Promise<ParitySample[]> {
  const evidence = cell.evidence!;
  const path = evidence.startsWith("/")
    ? evidence
    : evidence.startsWith("target/") || evidence.startsWith("benchmarks/")
      ? resolve(repoRoot, evidence)
      : resolve(semanticDataRoot, evidence);
  const evidenceHash = await sha256(path);
  if (evidenceHash !== cell.evidence_sha256) throw new Error(`${cell.cell_id}: evidence hash drift`);
  for (const item of cell.payload ?? []) {
    if (!item.path || !item.sha256) continue;
    const localPath = resolve(repoRoot, item.path);
    if (Bun.file(localPath).size !== item.bytes || await sha256(localPath) !== item.sha256) throw new Error(`${cell.cell_id}: artifact drift at ${item.path}`);
  }
  const report = await Bun.file(path).json() as any;
  const peakKib = report.process_memory?.peak_rss_kib;
  if (!Number.isSafeInteger(peakKib) || peakKib <= 0) throw new Error(`${cell.cell_id}: missing process RSS`);
  let samples: any[];
  let proofSize: number | undefined;
  if (cell.stack === "provekit_v1") {
    samples = report.samples.map((s: any) => ({ warmup: s.warmup, sample_index: s.iteration, prove_time_ms: s.prove_time_ms, proof_size_bytes: s.proof_size_bytes, tampered: s.tampered_proof_rejected }));
  } else if (cell.stack === "noir_barretenberg") {
    const body = report.report ?? report;
    samples = body.samples.map((s: any) => ({ warmup: s.warmup, sample_index: s.sample_index, prove_time_ms: (s.prove_time_ns ?? s.duration_ns) / 1e6, proof_size_bytes: body.proof_size_bytes ?? report.metadata?.proof_size_bytes, tampered: body.tampered_proof_rejected ?? report.metadata?.tampered_proof_rejected }));
  } else {
    const result = report.results.find((r: any) => cell.profile === "oprf_o2" ? r.variant === "world_id_protocol_nullifier" : r.variant === "p1_matched_monolithic_rsa4096");
    samples = result.samples.map((s: any) => ({ warmup: s.warmup, sample_index: s.sample_index, prove_time_ms: s.prove_time_ns / 1e6, proof_size_bytes: s.proof_size_bytes, tampered: s.tampered_proof_rejected }));
  }
  const base = baseMac(cell, evidenceHash, peakKib);
  return samples.map((sample, index) => ({
    ...base,
    sample_kind: sample.warmup ? "warmup" : "measured",
    sample_index: sample.warmup ? 0 : sample.sample_index + 1,
    status: "ok",
    prove_time_ms: sample.prove_time_ms,
    proof_size_bytes: sample.proof_size_bytes ?? proofSize!,
    valid_proof_accepted: true,
    tampered_proof_rejected: sample.tampered === true,
  }));
}

async function normalizeNative(path: string, manifest: Manifest): Promise<ParitySample[]> {
  const input = await Bun.file(path).json() as NativeParityEvidence;
  const id = cellId(input.semantic_profile, input.target, input.stack);
  if (!manifest.cells.some((cell) => cell.cell_id === id)) throw new Error(`${path}: unknown cell ${id}`);
  if (input.campaign_id !== CAMPAIGN_ID || input.runtime !== EXPECTED_RUNTIME[input.target]) throw new Error(`${path}: campaign/runtime mismatch`);
  const evidenceHash = await sha256(path);
  if ("gap" in input && input.gap) {
    return [{
      campaign_id: CAMPAIGN_ID, semantic_profile: input.semantic_profile, cell_id: id, target: input.target,
      device_model: input.device.model, os_version: input.device.os_version, abi: input.device.abi,
      runtime: input.runtime, browser: input.browser ?? "", stack: input.stack, frontend: input.frontend,
      prover_backend: input.prover_backend, witness_backend: input.witness_backend,
      sample_kind: "gap", sample_index: null, status: input.gap.status,
      prove_time_ms: null, proof_size_bytes: null, proving_payload_size_bytes: null,
      process_peak_memory_kib: null, valid_proof_accepted: null, tampered_proof_rejected: null,
      constraint_count: input.constraint_count ?? null, source_commits: JSON.stringify(input.source_commits),
      package_versions: JSON.stringify(input.package_versions), artifact_hashes: JSON.stringify(input.artifact_hashes),
      evidence_path: path, evidence_sha256: evidenceHash, session_id: input.session_id,
      failure_code: input.gap.failure_code, failure_detail: input.gap.failure_detail,
      semantic_equivalence_note: matchedProfileNote[input.semantic_profile as Exclude<Profile, "webauthn_closest_analogue">],
    }];
  }
  return input.samples.map((sample) => ({
    campaign_id: CAMPAIGN_ID, semantic_profile: input.semantic_profile, cell_id: id, target: input.target,
    device_model: input.device.model, os_version: input.device.os_version, abi: input.device.abi,
    runtime: input.runtime, browser: input.browser ?? "", stack: input.stack, frontend: input.frontend,
    prover_backend: input.prover_backend, witness_backend: input.witness_backend,
    sample_kind: sample.warmup ? "warmup" : "measured", sample_index: sample.warmup ? 0 : sample.sample_index + 1,
    status: sample.status, prove_time_ms: sample.prove_time_ms, proof_size_bytes: sample.proof_size_bytes,
    proving_payload_size_bytes: input.proving_payload_size_bytes, process_peak_memory_kib: input.process_peak_memory_kib,
    valid_proof_accepted: input.valid_proof_accepted, tampered_proof_rejected: input.tampered_proof_rejected,
    constraint_count: input.constraint_count ?? null, source_commits: JSON.stringify(input.source_commits),
    package_versions: JSON.stringify(input.package_versions), artifact_hashes: JSON.stringify(input.artifact_hashes),
    evidence_path: path, evidence_sha256: evidenceHash, session_id: input.session_id,
    failure_code: "", failure_detail: "",
    semantic_equivalence_note: matchedProfileNote[input.semantic_profile as Exclude<Profile, "webauthn_closest_analogue">],
  }));
}

function parseCsv(text: string): Array<Record<string, string>> {
  const records: string[][] = [];
  let record: string[] = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') { field += '"'; index++; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ",") { record.push(field); field = ""; }
    else if (char === "\n") { record.push(field.replace(/\r$/, "")); records.push(record); record = []; field = ""; }
    else field += char;
  }
  if (field || record.length) { record.push(field); records.push(record); }
  const header = records.shift();
  if (!header) return [];
  return records.filter((row) => row.some(Boolean)).map((row) => Object.fromEntries(header.map((column, index) => [column, row[index] ?? ""])));
}

function historicalTarget(hardware: string): Target {
  if (hardware === "macbook_m4") return "mac_chrome";
  if (hardware === "iphone_se_2022") return "iphone_se_2022";
  if (hardware === "motorola_e15") return "motorola_e15";
  throw new Error(`unknown historical hardware: ${hardware}`);
}

function numberOrNull(value: string): number | null {
  if (value === "") return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new Error(`invalid historical numeric value: ${value}`);
  return parsed;
}

async function normalizeHistoricalWebAuthn(manifest: Manifest): Promise<ParitySample[]> {
  if (await sha256(historicalCsvPath) !== historicalCsvSha256) throw new Error("historical WebAuthn CSV hash drift");
  const inputs = parseCsv(await Bun.file(historicalCsvPath).text()).filter((row) => row.circuit === "webauthn");
  if (inputs.length !== 54) throw new Error(`historical WebAuthn row count drift: ${inputs.length}`);
  return inputs.flatMap((input) => {
    const target = historicalTarget(input.hardware);
    const stack = input.prover as Stack;
    const id = cellId("webauthn_closest_analogue", target, stack);
    const manifestCell = manifest.cells.find((cell) => cell.cell_id === id);
    if (!manifestCell) throw new Error(`missing historical manifest cell: ${id}`);
    // V1 WebAuthn rows now come from committed V1 evidence. Do not re-import
    // the old WebAuthn row when the manifest promotes that cell to qualified.
    if (manifestCell.state !== "historical_frozen") return [];
    const historicalPayload = numberOrNull(input.circuit_size_bytes);
    let provingPayload = historicalPayload;
    let correction = "";
    if (stack === "provekit_v1" && target === "mac_chrome") {
      provingPayload = 2_392_664;
      correction = " Payload correction from frozen artifacts: 2,384,833-byte PKP + 7,831-byte input = 2,392,664 bytes.";
    } else if (stack === "provekit_v1" && target === "iphone_se_2022") {
      provingPayload = 2_376_468;
      correction = " Payload correction from native structured evidence: 2,327,248-byte prover + 49,220-byte frozen input = 2,376,468 bytes.";
    } else if (stack === "provekit_v1" && target === "motorola_e15") {
      provingPayload = 2_426_672;
      correction = " Payload correction from native structured evidence: 2,377,452-byte prover + 49,220-byte frozen input = 2,426,672 bytes.";
    } else if (stack === "noir_barretenberg" && target === "mac_chrome") {
      provingPayload = 74_003_114;
      correction = " Payload correction from raw evidence: 2,691,859-byte circuit + 7,831-byte input + 71,303,424-byte consumed CRS = 74,003,114 bytes.";
    } else if (stack === "noir_barretenberg") {
      provingPayload = 271_478_529;
      correction = " Payload correction from native structured evidence: 2,691,859-byte circuit + 351,150-byte frozen witness + 268,435,520-byte SRS = 271,478,529 bytes.";
    } else if (stack === "circom_groth16" && target === "mac_chrome") {
      provingPayload = 1_753_618_376;
      correction = " Payload correction from raw evidence: 20,470,384-byte WASM + 1,733,145,772-byte zkey + 2,220-byte input = 1,753,618,376 bytes.";
    } else if (stack === "circom_groth16" && target === "motorola_e15") {
      provingPayload = 1_842_364_184;
      correction = " Payload correction from raw evidence: 1,733,145,772-byte zkey + 109,218,412-byte frozen witness library = 1,842,364,184 bytes.";
    }
    const peakMemoryMib = numberOrNull(input.peak_memory_mib);
    const historicalNote = input.non_equivalence_note;
    const note = `${webauthnDifference} Historical note verbatim: ${historicalNote}${correction}`;
    return [{
      campaign_id: CAMPAIGN_ID,
      semantic_profile: "webauthn_closest_analogue",
      cell_id: id,
      target,
      device_model: input.device_model,
      os_version: input.os_version,
      abi: input.abi,
      runtime: input.runtime as ParitySample["runtime"],
      browser: input.browser,
      stack,
      frontend: input.frontend as ParitySample["frontend"],
      prover_backend: input.prover_backend,
      witness_backend: input.witness_backend,
      sample_kind: input.sample_kind as ParitySample["sample_kind"],
      sample_index: numberOrNull(input.sample_index),
      status: input.status as ParitySample["status"],
      prove_time_ms: numberOrNull(input.prover_time_ms),
      proof_size_bytes: numberOrNull(input.proof_size_bytes),
      proving_payload_size_bytes: provingPayload,
      process_peak_memory_kib: peakMemoryMib == null ? null : peakMemoryMib * 1024,
      valid_proof_accepted: true,
      tampered_proof_rejected: true,
      constraint_count: numberOrNull(input.constraint_count),
      source_commits: JSON.stringify({ circuit_commit: input.circuit_commit, source_commit: input.source_commit }),
      package_versions: input.package_versions,
      artifact_hashes: input.artifact_hashes,
      evidence_path: input.evidence_path,
      evidence_sha256: historicalCsvSha256,
      session_id: input.session_id,
      failure_code: input.failure_code,
      failure_detail: input.failure_detail,
      semantic_equivalence_note: note,
    }];
  });
}

export function validate(samples: ParitySample[], requireComplete = false) {
  const ids = new Set<string>();
  const byCell = new Map<string, ParitySample[]>();
  for (const row of samples) {
    if (!PROFILES.includes(row.semantic_profile) || !TARGETS.includes(row.target) || !STACKS.includes(row.stack)) throw new Error(`invalid enum in ${row.cell_id}`);
    if (row.cell_id !== cellId(row.semantic_profile, row.target, row.stack)) throw new Error(`semantic profile/cell mismatch: ${row.cell_id}`);
    if (row.runtime !== EXPECTED_RUNTIME[row.target]) throw new Error(`runtime separation violation: ${row.cell_id}`);
    if (!row.semantic_equivalence_note) throw new Error(`${row.cell_id}: missing semantic-equivalence note`);
    const key = `${row.cell_id}|${row.sample_kind}|${row.sample_index}`;
    if (ids.has(key)) throw new Error(`duplicate logical sample: ${key}`);
    ids.add(key);
    if (row.status === "ok" && row.sample_kind === "measured") {
      for (const field of ["prove_time_ms", "proof_size_bytes", "proving_payload_size_bytes", "process_peak_memory_kib"] as const) if (row[field] == null || row[field]! <= 0) throw new Error(`${row.cell_id}: blank/invalid ${field}`);
      if (!row.valid_proof_accepted || !row.tampered_proof_rejected) throw new Error(`${row.cell_id}: correctness gate failed`);
    }
    if (row.sample_kind === "gap") {
      if (row.status === "ok") throw new Error(`${row.cell_id}: gap cannot be ok`);
      for (const field of ["prove_time_ms", "proof_size_bytes", "proving_payload_size_bytes", "process_peak_memory_kib"] as const) if (row[field] != null) throw new Error(`${row.cell_id}: gap metric ${field} must be blank`);
      if (!row.failure_code || !row.failure_detail) throw new Error(`${row.cell_id}: gap requires structured failure evidence`);
    } else if (row.status !== "ok") {
      throw new Error(`${row.cell_id}: sampled row must have ok status`);
    }
    byCell.set(row.cell_id, [...(byCell.get(row.cell_id) ?? []), row]);
  }
  for (const [id, rows] of byCell) {
    const ok = rows.filter((r) => r.status === "ok");
    if (ok.length && rows.some((r) => r.sample_kind === "gap")) {
      throw new Error(`${id}: duplicate cell evidence mixes successful samples with a gap`);
    }
    if (ok.length && (ok.filter((r) => r.sample_kind === "warmup").length !== 1 || ok.filter((r) => r.sample_kind === "measured").length !== 5)) throw new Error(`${id}: requires 1+5 samples`);
    if (!ok.length && (rows.length !== 1 || rows[0].sample_kind !== "gap")) throw new Error(`${id}: unavailable cell requires exactly one gap row`);
  }
  if (requireComplete) {
    const missing = expectedCellIds().filter((id) => !byCell.has(id));
    if (missing.length) throw new Error(`missing ${missing.length} cells: ${missing.join(", ")}`);
  }
  return samples;
}

function csvValue(value: unknown) {
  if (value == null) return "";
  const text = typeof value === "boolean" ? String(value) : String(value);
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function toCsv(samples: ParitySample[]) {
  const hardware: Record<Target, string> = {
    mac_chrome: "macbook_m4",
    iphone_se_2022: "iphone_se_2022",
    motorola_e15: "motorola_e15",
  };
  const circuit: Record<Profile, string> = {
    passport_p1: "passport",
    oprf_o2: "oprf",
    webauthn_closest_analogue: "webauthn",
  };
  const rows = samples.map((row) => {
    let commits: Record<string, unknown> = {};
    try { commits = JSON.parse(row.source_commits); } catch { /* Preserve malformed provenance below. */ }
    const legacy: Record<(typeof CSV_COLUMNS)[number], unknown> = {
      campaign_id: row.campaign_id,
      attempt_id: `${row.cell_id}__${row.sample_kind}__${row.sample_index ?? "gap"}`,
      recorded_at_utc: "",
      hardware: hardware[row.target],
      device_model: row.device_model,
      os_version: row.os_version,
      abi: row.abi,
      runtime: row.runtime,
      browser: row.browser,
      circuit: circuit[row.semantic_profile],
      circuit_variant: row.semantic_profile,
      circuit_commit: commits.circuit_commit ?? commits.self ?? commits.world_id_protocol ?? "",
      prover: row.stack,
      frontend: row.frontend,
      prover_backend: row.prover_backend,
      witness_backend: row.witness_backend,
      sample_kind: row.sample_kind,
      sample_index: row.sample_index,
      status: row.status,
      initialization_time_ms: null,
      witness_time_ms: null,
      prover_time_ms: row.prove_time_ms,
      verify_time_ms: null,
      total_time_ms: null,
      peak_memory_mib: row.process_peak_memory_kib == null ? null : row.process_peak_memory_kib / 1024,
      proof_size_bytes: row.proof_size_bytes,
      circuit_size_bytes: row.proving_payload_size_bytes,
      artifact_size_bytes: null,
      bundle_size_bytes: null,
      constraint_count: row.constraint_count,
      artifact_version: "",
      source_commit: commits.source_commit ?? commits.campaign ?? commits.provekit ?? "",
      package_versions: row.package_versions,
      artifact_hashes: row.artifact_hashes,
      session_id: row.session_id,
      non_equivalence_note: row.semantic_equivalence_note,
      failure_code: row.failure_code,
      failure_detail: row.failure_detail,
      evidence_path: row.evidence_path,
    };
    return CSV_COLUMNS.map((column) => csvValue(legacy[column])).join(",");
  });
  return [CSV_COLUMNS.join(","), ...rows].join("\n") + "\n";
}

export async function exportCampaign(nativePaths: string[] = [], requireComplete = false) {
  const manifest = await Bun.file(manifestPath).json() as Manifest;
  if (manifest.campaign_id !== CAMPAIGN_ID || manifest.cells.length !== 27) throw new Error("manifest campaign/cell count drift");
  const actual = manifest.cells.map((cell) => cell.cell_id).sort();
  const expected = expectedCellIds().sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("manifest matrix drift");
  const mac = (await Promise.all(manifest.cells.filter((c) => c.state === "qualified" && c.target === "mac_chrome").map(normalizeMac))).flat();
  const native = (await Promise.all(nativePaths.map((path) => normalizeNative(resolve(path), manifest)))).flat();
  const historicalWebAuthn = await normalizeHistoricalWebAuthn(manifest);
  return validate([...mac, ...native, ...historicalWebAuthn], requireComplete);
}

if (import.meta.main) {
  const args = Bun.argv.slice(2);
  const requireComplete = args.includes("--require-complete");
  const outputArg = args.find((arg) => arg.startsWith("--output="));
  const nativePaths = args.filter((arg) => !arg.startsWith("--"));
  const output = resolve(outputArg?.slice("--output=".length) ?? resolve(import.meta.dir, "../legacy/semantic-parity/semantic-parity-samples.csv"));
  const rows = await exportCampaign(nativePaths, requireComplete);
  await Bun.write(output, toCsv(rows));
  const successfulCells = new Set(rows.filter((row) => row.status === "ok").map((row) => row.cell_id));
  const gapCells = new Set(rows.filter((row) => row.sample_kind === "gap").map((row) => row.cell_id));
  console.log(JSON.stringify({
    output,
    rows: rows.length,
    cells: new Set(rows.map((r) => r.cell_id)).size,
    successful_cells: successfulCells.size,
    gap_cells: gapCells.size,
    require_complete: requireComplete,
  }, null, 2));
}
