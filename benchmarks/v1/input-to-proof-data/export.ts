import { createHash } from "node:crypto";
import { basename, dirname, resolve } from "node:path";
import {
  CAMPAIGN_ID, CSV_COLUMNS, PROFILES, STACKS, TIMING_MODES, expectedSeries, seriesId,
  type Profile, type Stack, type Target, type TimingMode,
} from "./schema";

type CsvRow = Record<(typeof CSV_COLUMNS)[number], string | number | null | boolean>;
type RawSeries = {
  campaign_id: string;
  series_id: string;
  semantic_profile: Profile;
  target: Target;
  stack: Stack;
  timing_mode: TimingMode;
  created_at: string;
  environment: { device_model: string; os_version: string; abi: string; browser: string };
  attempts: Array<{ attempt_index: number; warmup: boolean | null; report: any }>;
};

const repoRoot = resolve(import.meta.dir, "../../..");
const rawRoot = resolve(
  process.env.INPUT_TO_PROOF_RAW_ROOT ??
    resolve(repoRoot, "target/v1-benchmarks/input-to-proof/mac-chrome"),
);
const output = resolve(import.meta.dir, "input-to-proof-samples.csv");
const iphoneRawRoot = resolve(
  process.env.INPUT_TO_PROOF_IPHONE_RAW_ROOT ??
    resolve(repoRoot, "target/v1-benchmarks/input-to-proof/iphone/publication"),
);
const e15RawRoot = resolve(
  process.env.INPUT_TO_PROOF_E15_RAW_ROOT ??
    resolve(repoRoot, "target/v1-benchmarks/input-to-proof/e15"),
);
const e15GapPath = resolve(import.meta.dir, "e15-webauthn-cold-gap.json");
const E15_OOM_GAP_SERIES = "webauthn_closest_analogue__motorola_e15__circom_groth16__cold_local";

const circuitIdentity: Record<Profile, { circuit: string; variant: string; commit: string; note: string }> = {
  passport_complete_age_check: {
    circuit: "passport_complete_age_check",
    variant: "historical-monolithic-age-integrity",
    commit: "9b2a6f37c67691eab4b0cec6c35e35c520e93285",
    note: "Historical monolithic Passport age and integrity lane retained separately from the additional exact P1 source pair.",
  },
  passport_p1: {
    circuit: "passport_age_integrity",
    variant: "P1-matched-monolithic-RSA4096",
    commit: "092621d721cfef9ff39b0787f5ba2c1f07eb6d95",
    note: "Matched P1 profile: monolithic RSA-4096 passport integrity, registry authorization, DG1 validity, and minimum-age assertion.",
  },
  oprf_o2: {
    circuit: "oprf_nullifier",
    variant: "O2-world-id-nullifier",
    commit: "85aeeef539961cae5a63de794997b507a5975717",
    note: "Matched O2 profile: World ID nullifier statement and frozen semantic inputs, including the same public nullifier.",
  },
  webauthn_closest_analogue: {
    circuit: "webauthn",
    variant: "closest-analogue",
    commit: "0fb5b4aa1398281c2fd3dbe14db147e05b61f201",
    note: "Closest analogue, not equivalent: Noir binds challenge, type, origin, RP-ID hash, flags, and public key; the Circom counterpart omits several bindings.",
  },
};

function sha256(path: string) {
  return Bun.file(path).arrayBuffer().then((bytes) => createHash("sha256").update(Buffer.from(bytes)).digest("hex"));
}

function selectCircomResult(profile: Profile, report: any) {
  if (profile === "passport_p1") return report.results.find((r: any) => r.variant === "p1_matched_monolithic_rsa4096") ?? report.results[0];
  if (profile === "oprf_o2") return report.results.find((r: any) => r.variant === "world_id_protocol_nullifier");
  return report.results[0];
}

function combineCircomPassport(report: any) {
  const registration = report.results.find((r: any) => r.variant === "self_passport_registration");
  const disclosure = report.results.find((r: any) => r.variant === "self_passport_disclosure");
  if (!registration || !disclosure) throw new Error("passport_complete_age_check: missing registration/disclosure pair");
  return registration.samples.map((left: any, index: number) => {
    const right = disclosure.samples[index];
    if (!right || left.warmup !== right.warmup || left.sample_index !== right.sample_index) {
      throw new Error("passport_complete_age_check: staged Circom sample mismatch");
    }
    return {
      warmup: left.warmup,
      initialization: (left.initialization_time_ns + right.initialization_time_ns) / 1e6,
      witness: (left.witness_time_ns + right.witness_time_ns) / 1e6,
      prove: (left.prove_time_ns + right.prove_time_ns) / 1e6,
      verify: (left.verify_time_ns + right.verify_time_ns) / 1e6,
      outer: (left.input_to_proof_time_ns + right.input_to_proof_time_ns) / 1e6,
      proof: left.proof_size_bytes + right.proof_size_bytes,
      payload: registration.artifacts.proving_payload_size_bytes + disclosure.artifacts.proving_payload_size_bytes,
      artifact: registration.artifacts.zkey_size_bytes + disclosure.artifacts.zkey_size_bytes,
      bundle: registration.artifacts.proving_payload_size_bytes + disclosure.artifacts.proving_payload_size_bytes,
      constraints: null,
      tampered: left.tampered_proof_rejected && right.tampered_proof_rejected,
    };
  });
}

function reportSamples(profile: Profile, stack: Stack, report: any) {
  if (stack === "provekit_v1") {
    const payload = report.artifacts.proving_payload_size_bytes;
    return report.samples.map((sample: any) => ({
      warmup: sample.warmup,
      initialization: sample.prepare_time_ms,
      witness: sample.witness_time_ms,
      prove: sample.prove_time_ms,
      verify: sample.verify_time_ms,
      outer: sample.input_to_proof_time_ms,
      proof: sample.proof_size_bytes,
      payload,
      artifact: report.artifacts.prover_bytes,
      bundle: report.bundle.cold_download_bytes,
      constraints: report.circuit.constraints,
      tampered: sample.tampered_proof_rejected,
    }));
  }
  if (stack === "noir_barretenberg") {
    const crs = report.proving_payload_transport?.crs_size_bytes ?? 0;
    const circuit = report.metadata.circuit_size_bytes;
    const input = report.metadata.input_size_bytes;
    return report.samples.map((sample: any) => ({
      warmup: sample.warmup,
      initialization: sample.initialization_time_ns / 1e6,
      witness: sample.witness_time_ns / 1e6,
      prove: sample.prove_time_ns / 1e6,
      verify: sample.verify_time_ns / 1e6,
      outer: sample.input_to_proof_time_ns / 1e6,
      proof: sample.proof_size_bytes,
      payload: circuit + input + crs,
      artifact: circuit + crs,
      bundle: circuit + input + crs,
      constraints: null,
      tampered: sample.tampered_proof_rejected,
    }));
  }
  if (profile === "passport_complete_age_check") return combineCircomPassport(report);
  const result = selectCircomResult(profile, report);
  if (!result) throw new Error(`${profile}: missing selected Circom result`);
  return result.samples.map((sample: any) => ({
    warmup: sample.warmup,
    initialization: sample.initialization_time_ns / 1e6,
    witness: sample.witness_time_ns / 1e6,
    prove: sample.prove_time_ns / 1e6,
    verify: sample.verify_time_ns / 1e6,
    outer: sample.input_to_proof_time_ns / 1e6,
    proof: sample.proof_size_bytes,
    payload: result.artifacts.proving_payload_size_bytes,
    artifact: result.artifacts.zkey_size_bytes,
    bundle: result.artifacts.proving_payload_size_bytes,
    constraints: null,
    tampered: sample.tampered_proof_rejected,
  }));
}

function identity(stack: Stack) {
  if (stack === "provekit_v1") return ["noir", "provekit-v1-whir-wasm-single-thread", "@noir-lang/noir_js@1.0.0-beta.11"];
  if (stack === "noir_barretenberg") return ["noir", "barretenberg-ultrahonk-wasm-single-thread", "@noir-lang/noir_js@1.0.0-beta.19"];
  return ["circom", "snarkjs-groth16-browser-wasm-single-thread", "circom-witness-wasm"];
}

function packages(stack: Stack) {
  if (stack === "provekit_v1") return JSON.stringify({ provekit: "9b2a6f37c67691eab4b0cec6c35e35c520e93285", noir_js: "1.0.0-beta.11" });
  if (stack === "noir_barretenberg") return JSON.stringify({ bb_js: "4.2.0-aztecnr-rc.2", noir_js: "1.0.0-beta.19" });
  return JSON.stringify({ circom: "2.2.2", snarkjs: "0.7.6" });
}

const iosFunctions: Record<string, { profile: Profile; stack: Stack; component?: "registration" | "disclosure" }> = {
  "bench_mobile::bench_passport_complete_age_check_input_to_proof": { profile: "passport_complete_age_check", stack: "provekit_v1" },
  "bench_mobile::bench_passport_p1_input_to_proof": { profile: "passport_p1", stack: "provekit_v1" },
  "bench_mobile::bench_webauthn_assertion_input_to_proof": { profile: "webauthn_closest_analogue", stack: "provekit_v1" },
  "bench_mobile::bench_oprf_input_to_proof": { profile: "oprf_o2", stack: "provekit_v1" },
  "provekit_v1_mobile_adapters::bench_passport_barretenberg_input_to_proof": { profile: "passport_complete_age_check", stack: "noir_barretenberg" },
  "provekit_v1_mobile_adapters::bench_passport_p1_barretenberg_input_to_proof": { profile: "passport_p1", stack: "noir_barretenberg" },
  "provekit_v1_mobile_adapters::bench_webauthn_barretenberg_input_to_proof": { profile: "webauthn_closest_analogue", stack: "noir_barretenberg" },
  "provekit_v1_mobile_adapters::bench_oprf_barretenberg_input_to_proof": { profile: "oprf_o2", stack: "noir_barretenberg" },
  "provekit_v1_rapidsnark_mobile::bench_passport_rapidsnark_input_to_proof": { profile: "passport_complete_age_check", stack: "circom_groth16", component: "disclosure" },
  "provekit_v1_rapidsnark_mobile_register::bench_passport_rapidsnark_input_to_proof": { profile: "passport_complete_age_check", stack: "circom_groth16", component: "registration" },
  "provekit_v1_rapidsnark_mobile::bench_passport_p1_rapidsnark_input_to_proof": { profile: "passport_p1", stack: "circom_groth16" },
  "provekit_v1_rapidsnark_mobile_webauthn::bench_webauthn_rapidsnark_input_to_proof": { profile: "webauthn_closest_analogue", stack: "circom_groth16" },
  "provekit_v1_rapidsnark_mobile_oprf::bench_oprf_nullifier_rapidsnark_input_to_proof": { profile: "oprf_o2", stack: "circom_groth16" },
};

type IosReportEvidence = {
  path: string;
  buildPath: string;
  sessionPath: string;
  buildId: string;
  sessionId: string;
  invocation: number | null;
  mode: TimingMode;
  report: any;
  build: any;
  session: any;
};

function rowTarget(row: CsvRow): Target {
  if (row.hardware === "macbook_m4") return "mac_chrome";
  if (row.hardware === "iphone_se_2022") return "iphone_se_2022";
  return "motorola_e15";
}

function nativeIdentity(profile: Profile, stack: Stack) {
  if (stack === "provekit_v1") return ["noir", "provekit-v1-whir-native", "integrated-noir-beta11-witness"];
  if (stack === "noir_barretenberg") return ["noir", "barretenberg-rs-4.2.0-aztecnr-rc.2", "acvm-beta19"];
  if (profile === "oprf_o2") return ["circom", "rust-rapidsnark-0.1.4", "wasmi-0.46.0-circom-wasm"];
  return ["circom", "rust-rapidsnark-0.1.4", "rust-witness-0.1.6"];
}

function nativePackages(profile: Profile, stack: Stack) {
  if (stack === "provekit_v1") return JSON.stringify({ provekit: "9b2a6f37c67691eab4b0cec6c35e35c520e93285", mobench: "0.1.48", noir: "1.0.0-beta.11" });
  if (stack === "noir_barretenberg") return JSON.stringify({ mopro: "0.3.7", barretenberg_rs: "4.2.0-aztecnr-rc.2", noir: "1.0.0-beta.19" });
  if (profile === "oprf_o2") return JSON.stringify({ rust_rapidsnark: "0.1.4", wasmi: "0.46.0", circom: "2.2.2" });
  return JSON.stringify({ rust_rapidsnark: "0.1.4", rust_witness: "0.1.6", circom: "2.2.2" });
}

function iosSamples(evidence: IosReportEvidence, definition: (typeof iosFunctions)[string]) {
  const custom = evidence.report.custom_metrics;
  const run = custom?.run_u64 ?? {};
  const values = custom?.sample_u64 ?? {};
  const total: number[] = values.input_to_proof_time_ns ?? [];
  const proofs: number[] = values.proof_size_bytes ?? [];
  const witness: number[] = values.witness_time_ns ?? [];
  const prove: number[] = values.prove_time_ns ?? [];
  if (!total.length || total.length !== proofs.length || total.length !== prove.length) {
    throw new Error(`${evidence.path}: incomplete input-to-proof custom metrics`);
  }
  const warmups = Number(evidence.report.spec?.warmup ?? 0);
  const measuredResources: any[] = evidence.report.samples ?? [];
  return total.map((inputToProofNs, index) => {
    const warmup = index < warmups;
    const measuredIndex = index - warmups;
    const resource = warmup ? null : measuredResources[measuredIndex];
    const artifact = definition.stack === "provekit_v1"
      ? run.prover_size_bytes
      : definition.stack === "noir_barretenberg"
        ? Number(run.circuit_size_bytes) + Number(run.srs_size_bytes)
        : run.zkey_size_bytes;
    return {
      warmup,
      witness: definition.stack === "provekit_v1" ? null : witness[index] / 1e6,
      prove: prove[index] / 1e6,
      outer: inputToProofNs / 1e6,
      proof: proofs[index],
      payload: run.proving_payload_size_bytes,
      artifact,
      bundle: run.proving_payload_size_bytes,
      peak: resource?.process_peak_memory_kb == null ? null : resource.process_peak_memory_kb / 1024,
    };
  });
}

function combineIosPassport(left: ReturnType<typeof iosSamples>[number], right: ReturnType<typeof iosSamples>[number]) {
  if (left.warmup !== right.warmup) throw new Error("iPhone staged Passport sample mismatch");
  return {
    warmup: left.warmup,
    witness: Number(left.witness) + Number(right.witness),
    prove: left.prove + right.prove,
    outer: left.outer + right.outer,
    proof: left.proof + right.proof,
    payload: left.payload + right.payload,
    artifact: left.artifact + right.artifact,
    bundle: left.bundle + right.bundle,
    peak: left.peak == null || right.peak == null ? null : Math.max(left.peak, right.peak),
  };
}

async function loadIosEvidence() {
  const evidence: IosReportEvidence[] = [];
  const glob = new Bun.Glob("**/bench-report.json");
  for await (const relative of glob.scan({ cwd: iphoneRawRoot, onlyFiles: true })) {
    const path = resolve(iphoneRawRoot, relative);
    const sessionRoot = dirname(path);
    const buildRoot = dirname(sessionRoot);
    const rawReport = await Bun.file(path).json();
    const reports = normalizeIosReports(rawReport);
    if (!reports.some((report) => iosFunctions[report.function])) continue;
    const sessionPath = resolve(sessionRoot, "session.json");
    const buildPath = resolve(buildRoot, "build.json");
    if (!(await Bun.file(sessionPath).exists()) || !(await Bun.file(buildPath).exists())) {
      throw new Error(`${path}: missing BrowserStack session/build provenance`);
    }
    const session = await Bun.file(sessionPath).json();
    const build = await Bun.file(buildPath).json();
    if (session.status !== "passed" || build.status !== "passed") throw new Error(`${path}: BrowserStack run did not pass`);
    const device = build.devices?.[0];
    if (device?.device !== "iPhone SE 2022" || !String(device?.os_version ?? "").startsWith("15.")) {
      throw new Error(`${path}: unexpected BrowserStack device identity`);
    }
    const coldMatch = relative.match(/(?:^|\/)cold\/run-(\d+)(?:\/|$)/);
    const coldBatch = relative.match(/(?:^|\/)cold\/batch(?:\/|$)/);
    reports.forEach((report, reportIndex) => {
      if (!iosFunctions[report.function]) return;
      evidence.push({
        path,
        buildPath,
        sessionPath,
        buildId: build.id ?? basename(buildRoot),
        sessionId: session.id ?? basename(sessionRoot).replace(/^session-/, ""),
        invocation: coldMatch ? Number(coldMatch[1]) : coldBatch ? reportIndex : null,
        mode: coldMatch || coldBatch ? "cold_local" : "warm_reuse",
        report,
        build,
        session,
      });
    });
  }
  return evidence;
}

export function normalizeIosReports(rawReport: unknown): Record<string, any>[] {
  const reports = Array.isArray(rawReport) ? rawReport : [rawReport];
  if (!reports.every((report) => report && typeof report === "object" && !Array.isArray(report))) {
    throw new Error("iPhone benchmark report must be a JSON object or array of JSON objects");
  }
  return reports;
}

export function validateRows(rows: CsvRow[], expected = expectedSeries(["mac_chrome"])) {
  const grouped = new Map<string, CsvRow[]>();
  const duplicates = new Set<string>();
  for (const row of rows) {
    const profile = row.circuit === "passport_complete_age_check"
      ? "passport_complete_age_check"
      : row.circuit === "passport_age_integrity"
        ? "passport_p1"
        : row.circuit === "oprf_nullifier"
          ? "oprf_o2"
          : "webauthn_closest_analogue";
    const id = seriesId(profile, rowTarget(row), row.prover as Stack, row.timing_mode as TimingMode);
    const key = `${id}|${row.sample_kind}|${row.sample_index}`;
    if (duplicates.has(key)) throw new Error(`duplicate sample ${key}`);
    duplicates.add(key);
    grouped.set(id, [...(grouped.get(id) ?? []), row]);
    if (row.sample_kind === "gap") {
      if (id !== E15_OOM_GAP_SERIES || row.status !== "runtime_failed" || row.failure_code !== "out_of_memory" || !row.failure_detail) {
        throw new Error(`${id}: invalid gap status`);
      }
      for (const metric of ["prover_time_ms", "total_time_ms", "input_to_proof_time_ms", "proof_size_bytes", "circuit_size_bytes", "peak_memory_mib"] as const) {
        if (row[metric] != null && row[metric] !== "") throw new Error(`${id}: gap ${metric} must be blank`);
      }
    } else {
      for (const metric of ["prover_time_ms", "total_time_ms", "input_to_proof_time_ms", "proof_size_bytes", "circuit_size_bytes"] as const) {
        if (typeof row[metric] !== "number" || row[metric]! <= 0) throw new Error(`${id}: invalid ${metric}`);
      }
      if (row.sample_kind === "measured" && (typeof row.peak_memory_mib !== "number" || row.peak_memory_mib <= 0)) throw new Error(`${id}: invalid peak_memory_mib`);
      if (row.prover !== "provekit_v1" && (typeof row.witness_time_ms !== "number" || row.witness_time_ms <= 0)) throw new Error(`${id}: invalid witness_time_ms`);
      if (Math.abs(Number(row.total_time_ms) - Number(row.input_to_proof_time_ms)) > 0.001) throw new Error(`${id}: headline mismatch`);
    }
  }
  for (const id of expected) {
    const series = grouped.get(id) ?? [];
    const gaps = series.filter((r) => r.sample_kind === "gap");
    if (gaps.length === 1 && series.length === 1) continue;
    if (gaps.length) throw new Error(`${id}: gap cannot be mixed with attempts`);
    if (series.filter((r) => r.sample_kind === "warmup").length !== 1) throw new Error(`${id}: expected one warmup`);
    if (series.filter((r) => r.sample_kind === "measured").length !== 5) throw new Error(`${id}: expected five measured samples`);
  }
  if (grouped.size !== expected.length) throw new Error(`expected ${expected.length} series, found ${grouped.size}`);
}

function csvValue(value: unknown) {
  if (value == null) return "";
  const string = String(value);
  return /[",\n]/.test(string) ? `"${string.replaceAll('"', '""')}"` : string;
}

export async function buildMacRows() {
  const rows: CsvRow[] = [];
  for (const profile of PROFILES) for (const stack of STACKS) for (const mode of TIMING_MODES) {
    const id = seriesId(profile, "mac_chrome", stack, mode);
    const path = resolve(rawRoot, `${id}.json`);
    if (!(await Bun.file(path).exists())) throw new Error(`missing raw series ${path}`);
    const series = await Bun.file(path).json() as RawSeries;
    if (series.campaign_id !== CAMPAIGN_ID || series.series_id !== id) throw new Error(`${id}: identity mismatch`);
    const evidenceHash = await sha256(path);
    const extracted = series.attempts.flatMap((attempt) =>
      reportSamples(profile, stack, attempt.report).map((sample: any) => ({ attempt, sample })),
    );
    if (extracted.length !== 6) throw new Error(`${id}: expected six attempts, found ${extracted.length}`);
    const [frontend, proverBackend, witnessBackend] = identity(stack);
    const circuit = circuitIdentity[profile];
    extracted.forEach(({ attempt, sample }, index) => {
      const warmup = mode === "cold_local" ? attempt.warmup === true : sample.warmup === true;
      const peakKib = attempt.report.process_memory?.peak_rss_kib;
      const row: CsvRow = {
        campaign_id: CAMPAIGN_ID,
        attempt_id: `${id}-${index}`,
        recorded_at_utc: series.created_at,
        hardware: "macbook_m4",
        device_model: series.environment.device_model,
        os_version: series.environment.os_version,
        abi: series.environment.abi,
        runtime: "browser_wasm",
        browser: series.environment.browser,
        circuit: circuit.circuit,
        circuit_variant: circuit.variant,
        circuit_commit: circuit.commit,
        prover: stack,
        frontend,
        prover_backend: proverBackend,
        witness_backend: witnessBackend,
        sample_kind: warmup ? "warmup" : "measured",
        sample_index: warmup ? 0 : mode === "cold_local" ? index : Number(sample.warmup ? 0 : index),
        status: "ok",
        initialization_time_ms: sample.initialization,
        witness_time_ms: sample.witness,
        prover_time_ms: sample.prove,
        verify_time_ms: sample.verify,
        total_time_ms: sample.outer,
        peak_memory_mib: peakKib / 1024,
        proof_size_bytes: sample.proof,
        circuit_size_bytes: sample.payload,
        artifact_size_bytes: sample.artifact,
        bundle_size_bytes: sample.bundle,
        constraint_count: sample.constraints,
        artifact_version: "input-to-proof-v1",
        source_commit: stack === "provekit_v1" ? "9b2a6f37c67691eab4b0cec6c35e35c520e93285" : circuit.commit,
        package_versions: packages(stack),
        artifact_hashes: JSON.stringify({ raw_evidence_sha256: evidenceHash }),
        session_id: "",
        non_equivalence_note: circuit.note,
        failure_code: "",
        failure_detail: "",
        evidence_path: path,
        timing_mode: mode,
        input_to_proof_time_ms: sample.outer,
      };
      if (!sample.tampered) throw new Error(`${id}: tamper rejection missing`);
      rows.push(row);
    });
  }
  return rows;
}

export async function buildIphoneRows() {
  const evidence = await loadIosEvidence();
  const rows: CsvRow[] = [];
  for (const profile of PROFILES) for (const stack of STACKS) for (const mode of TIMING_MODES) {
    const id = seriesId(profile, "iphone_se_2022", stack, mode);
    const definitions = Object.entries(iosFunctions).filter(([, value]) => value.profile === profile && value.stack === stack);
    const matching = evidence.filter((item) => {
      const definition = iosFunctions[item.report.function];
      return item.mode === mode && definition?.profile === profile && definition.stack === stack;
    });
    const expectedReports = definitions.length * (mode === "cold_local" ? 6 : 1);
    if (matching.length !== expectedReports) {
      throw new Error(`${id}: expected ${expectedReports} BrowserStack reports, found ${matching.length}`);
    }

    const extracted: Array<{ sample: ReturnType<typeof iosSamples>[number]; evidence: IosReportEvidence[] }> = [];
    if (definitions.length === 1) {
      for (const item of matching.sort((a, b) => Number(a.invocation) - Number(b.invocation))) {
        extracted.push(...iosSamples(item, iosFunctions[item.report.function]).map((sample) => ({ sample, evidence: [item] })));
      }
    } else {
      const invocations = mode === "cold_local" ? [0, 1, 2, 3, 4, 5] : [null];
      for (const invocation of invocations) {
        const components = matching.filter((item) => item.invocation === invocation);
        const registration = components.find((item) => iosFunctions[item.report.function].component === "registration");
        const disclosure = components.find((item) => iosFunctions[item.report.function].component === "disclosure");
        if (!registration || !disclosure) throw new Error(`${id}: missing staged Passport component for invocation ${invocation}`);
        const left = iosSamples(registration, iosFunctions[registration.report.function]);
        const right = iosSamples(disclosure, iosFunctions[disclosure.report.function]);
        if (left.length !== right.length) throw new Error(`${id}: staged Passport sample count mismatch`);
        extracted.push(...left.map((sample, index) => ({ sample: combineIosPassport(sample, right[index]), evidence: [registration, disclosure] })));
      }
    }
    if (extracted.length !== 6) throw new Error(`${id}: expected six attempts, found ${extracted.length}`);

    const [frontend, proverBackend, witnessBackend] = nativeIdentity(profile, stack);
    const circuit = circuitIdentity[profile];
    for (let index = 0; index < extracted.length; index++) {
      const item = extracted[index];
      const isWarmup = mode === "cold_local" ? index === 0 : item.sample.warmup;
      const evidenceHashes = await Promise.all(item.evidence.map(async (value) => ({
        report_sha256: await sha256(value.path),
        session_sha256: await sha256(value.sessionPath),
        build_sha256: await sha256(value.buildPath),
      })));
      const first = item.evidence[0];
      const device = first.build.devices?.[0];
      const recordedAt = new Date(first.session.start_time ?? first.build.start_time).toISOString();
      rows.push({
        campaign_id: CAMPAIGN_ID,
        attempt_id: `${id}-${index}`,
        recorded_at_utc: recordedAt,
        hardware: "iphone_se_2022",
        device_model: device?.device ?? "iPhone SE 2022",
        os_version: device?.os_version ?? "15",
        abi: "arm64",
        runtime: "ios_native",
        browser: "",
        circuit: circuit.circuit,
        circuit_variant: circuit.variant,
        circuit_commit: circuit.commit,
        prover: stack,
        frontend,
        prover_backend: proverBackend,
        witness_backend: witnessBackend,
        sample_kind: isWarmup ? "warmup" : "measured",
        sample_index: isWarmup ? 0 : index,
        status: "ok",
        initialization_time_ms: null,
        witness_time_ms: item.sample.witness,
        prover_time_ms: item.sample.prove,
        verify_time_ms: null,
        total_time_ms: item.sample.outer,
        peak_memory_mib: item.sample.peak,
        proof_size_bytes: item.sample.proof,
        circuit_size_bytes: item.sample.payload,
        artifact_size_bytes: item.sample.artifact,
        bundle_size_bytes: item.sample.bundle,
        constraint_count: null,
        artifact_version: "input-to-proof-v1",
        source_commit: stack === "provekit_v1" ? "9b2a6f37c67691eab4b0cec6c35e35c520e93285" : circuit.commit,
        package_versions: nativePackages(profile, stack),
        artifact_hashes: JSON.stringify({ raw_evidence_sha256: evidenceHashes }),
        session_id: item.evidence.map((value) => `${value.buildId}/${value.sessionId}`).join(";"),
        non_equivalence_note: `${circuit.note}${stack === "provekit_v1" ? " Native ProveKit exposes witness generation and proving as one integrated timed operation, so witness_time_ms is intentionally blank." : ""}`,
        failure_code: "",
        failure_detail: "",
        evidence_path: item.evidence.map((value) => value.path).join(";"),
        timing_mode: mode,
        input_to_proof_time_ms: item.sample.outer,
      });
    }
  }
  return rows;
}

type E15Evidence = {
  path: string;
  envelope: any;
  result: any;
};

const e15WarmPaths: Record<Profile, Record<Stack, string | [string, string]>> = {
  passport_complete_age_check: {
    provekit_v1: "publication/warm/provekit-passport-single-thread-v3-postreboot-20260809/results.json",
    noir_barretenberg: "publication/warm/barretenberg-passport-20260810/results.json",
    circom_groth16: ["publication/warm/circom-passport-register/results.json", "publication/warm/circom-passport-disclose/results.json"],
  },
  passport_p1: {
    provekit_v1: "publication/warm/provekit-passport-p1-v2-postreboot-20260809/results.json",
    noir_barretenberg: "publication/warm/barretenberg-passport-p1-20260810/results.json",
    circom_groth16: "publication/warm/circom-passport-p1/results.json",
  },
  oprf_o2: {
    provekit_v1: "publication/warm/provekit-oprf-v2-20260809/results.json",
    noir_barretenberg: "publication/warm/barretenberg-oprf-20260810/results.json",
    circom_groth16: "publication/warm/circom-oprf/results.json",
  },
  webauthn_closest_analogue: {
    provekit_v1: "publication/warm/provekit-webauthn-v2-postreboot-20260809/results.json",
    noir_barretenberg: "publication/warm/barretenberg-webauthn-20260810/results.json",
    circom_groth16: "publication/warm/circom-webauthn/results.json",
  },
};

const e15ColdDirectories: Record<Profile, Record<Stack, string | [string, string] | null>> = {
  passport_complete_age_check: {
    provekit_v1: "attempts/cold/passport",
    noir_barretenberg: "publication/cold/barretenberg-passport",
    circom_groth16: ["publication/cold/circom-passport-register", "publication/cold/circom-passport-disclose"],
  },
  passport_p1: {
    provekit_v1: "attempts/cold/passport-p1",
    noir_barretenberg: "publication/cold/barretenberg-passport-p1",
    circom_groth16: "publication/cold/circom-passport-p1",
  },
  oprf_o2: {
    provekit_v1: "attempts/cold/oprf",
    noir_barretenberg: "publication/cold/barretenberg-oprf",
    circom_groth16: "publication/cold/circom-oprf",
  },
  webauthn_closest_analogue: {
    provekit_v1: "attempts/cold/webauthn",
    noir_barretenberg: "publication/cold/barretenberg-webauthn",
    circom_groth16: null,
  },
};

const e15ProveKitColdReplacements: Partial<Record<Profile, Record<number, string>>> = {
  passport_complete_age_check: { 3: "attempts/cold-retry4-20260809/passport/run-3/results.json" },
  passport_p1: { 1: "attempts/cold-retry2-20260809/passport-p1/run-1/results.json" },
  oprf_o2: { 3: "attempts/cold-retry-20260809/oprf/run-3/results.json" },
  webauthn_closest_analogue: { 5: "attempts/cold-retry-20260809/webauthn/run-5/results.json" },
};

async function loadE15Evidence(relative: string): Promise<E15Evidence> {
  const path = resolve(e15RawRoot, relative);
  if (!(await Bun.file(path).exists())) throw new Error(`missing E15 evidence ${path}`);
  const envelope = await Bun.file(path).json();
  const successful = envelope.results?.filter((result: any) => result.status === "ok") ?? [];
  if (successful.length !== 1) throw new Error(`${path}: expected one successful result, found ${successful.length}`);
  return { path, envelope, result: successful[0] };
}

function e15Samples(stack: Stack, evidence: E15Evidence) {
  const report = evidence.result.report;
  const custom = report.custom_metrics;
  const run = custom?.run_u64 ?? {};
  const values = custom?.sample_u64 ?? {};
  const total: number[] = values.input_to_proof_time_ns ?? [];
  const proofs: number[] = values.proof_size_bytes ?? [];
  const prove: number[] = values.prove_time_ns ?? [];
  const witness: number[] = values.witness_time_ns ?? [];
  if (!total.length || total.length !== proofs.length || total.length !== prove.length) {
    throw new Error(`${evidence.path}: incomplete input-to-proof custom metrics`);
  }
  if (stack !== "provekit_v1" && witness.length !== total.length) throw new Error(`${evidence.path}: incomplete witness metrics`);
  const warmups = Number(report.spec?.warmup ?? 0);
  const resources: any[] = report.samples ?? [];
  return total.map((outer, index) => {
    const warmup = index < warmups;
    const resource = warmup ? null : resources[index - warmups];
    const artifact = stack === "provekit_v1"
      ? run.prover_size_bytes
      : stack === "noir_barretenberg"
        ? Number(run.circuit_size_bytes) + Number(run.srs_size_bytes)
        : run.zkey_size_bytes;
    return {
      warmup,
      witness: stack === "provekit_v1" ? null : witness[index] / 1e6,
      prove: prove[index] / 1e6,
      outer: outer / 1e6,
      proof: proofs[index],
      payload: run.proving_payload_size_bytes,
      artifact,
      bundle: run.proving_payload_size_bytes,
      peak: resource?.process_peak_memory_kb == null ? null : resource.process_peak_memory_kb / 1024,
    };
  });
}

async function e15EvidenceFor(profile: Profile, stack: Stack, mode: TimingMode) {
  const selected = mode === "warm_reuse" ? e15WarmPaths[profile][stack] : e15ColdDirectories[profile][stack];
  if (selected == null) return [];
  const components = Array.isArray(selected) ? selected : [selected];
  const attempts: E15Evidence[][] = [];
  if (mode === "warm_reuse") {
    attempts.push(await Promise.all(components.map(loadE15Evidence)));
  } else {
    for (let index = 0; index < 6; index++) {
      const replacement = stack === "provekit_v1" ? e15ProveKitColdReplacements[profile]?.[index] : undefined;
      attempts.push(await Promise.all(components.map((directory) => loadE15Evidence(replacement ?? `${directory}/run-${index}/results.json`))));
    }
  }
  return attempts;
}

export async function buildE15Rows() {
  const rows: CsvRow[] = [];
  for (const profile of PROFILES) for (const stack of STACKS) for (const mode of TIMING_MODES) {
    const id = seriesId(profile, "motorola_e15", stack, mode);
    const attempts = await e15EvidenceFor(profile, stack, mode);
    if (!attempts.length) {
      if (id !== E15_OOM_GAP_SERIES) throw new Error(`${id}: missing E15 evidence manifest`);
      const gap = await Bun.file(e15GapPath).json();
      if (gap.logical_series_id !== id || gap.status !== "runtime_failed" || gap.failure_code !== "out_of_memory") throw new Error(`${id}: invalid gap manifest`);
      const reportPath = resolve(repoRoot, gap.evidence.report_path);
      const logcatPath = resolve(repoRoot, gap.evidence.logcat_path);
      if (await sha256(reportPath) !== gap.evidence.report_sha256 || await sha256(logcatPath) !== gap.evidence.logcat_sha256) throw new Error(`${id}: gap evidence hash mismatch`);
      const failedEnvelope = await Bun.file(reportPath).json();
      rows.push({
        campaign_id: CAMPAIGN_ID, attempt_id: `${id}-gap`, recorded_at_utc: failedEnvelope.generated_at_utc, hardware: "motorola_e15",
        device_model: gap.device.model, os_version: gap.device.os, abi: gap.device.abi, runtime: gap.runtime, browser: "",
        circuit: gap.circuit, circuit_variant: gap.circuit_variant, circuit_commit: gap.circuit_commit, prover: gap.stack,
        frontend: gap.frontend, prover_backend: gap.prover_backend, witness_backend: gap.witness_backend, sample_kind: "gap",
        sample_index: null, status: gap.status, initialization_time_ms: null, witness_time_ms: null, prover_time_ms: null,
        verify_time_ms: null, total_time_ms: null, peak_memory_mib: null, proof_size_bytes: null, circuit_size_bytes: null,
        artifact_size_bytes: null, bundle_size_bytes: null, constraint_count: null, artifact_version: "input-to-proof-v1",
        source_commit: gap.circuit_commit, package_versions: nativePackages(profile, stack),
        artifact_hashes: JSON.stringify({ report_sha256: gap.evidence.report_sha256, logcat_sha256: gap.evidence.logcat_sha256 }),
        session_id: "", non_equivalence_note: gap.note, failure_code: gap.failure_code, failure_detail: gap.failure_detail,
        evidence_path: `${reportPath};${logcatPath}`, timing_mode: mode, input_to_proof_time_ms: null,
      });
      continue;
    }

    const extracted: Array<{ sample: ReturnType<typeof e15Samples>[number]; evidence: E15Evidence[] }> = [];
    for (const componentEvidence of attempts) {
      const componentSamples = componentEvidence.map((item) => e15Samples(stack, item));
      const count = componentSamples[0].length;
      if (!componentSamples.every((samples) => samples.length === count)) throw new Error(`${id}: staged sample count mismatch`);
      for (let index = 0; index < count; index++) {
        const parts = componentSamples.map((samples) => samples[index]);
        const sample = parts.length === 1 ? parts[0] : combineIosPassport(parts[0], parts[1]);
        extracted.push({ sample, evidence: componentEvidence });
      }
    }
    if (extracted.length !== 6) throw new Error(`${id}: expected six attempts, found ${extracted.length}`);
    const circuit = circuitIdentity[profile];
    const [frontend, proverBackend, witnessBackend] = nativeIdentity(profile, stack);
    for (let index = 0; index < extracted.length; index++) {
      const item = extracted[index];
      const isWarmup = mode === "cold_local" ? index === 0 : item.sample.warmup;
      const first = item.evidence[0];
      const hashes = await Promise.all(item.evidence.map(async (value) => ({ raw_evidence_sha256: await sha256(value.path) })));
      rows.push({
        campaign_id: CAMPAIGN_ID, attempt_id: `${id}-${index}`, recorded_at_utc: first.envelope.generated_at_utc,
        hardware: "motorola_e15", device_model: first.envelope.device.model, os_version: first.envelope.device.os,
        abi: first.envelope.device.abi, runtime: "android_native", browser: "", circuit: circuit.circuit,
        circuit_variant: circuit.variant, circuit_commit: circuit.commit, prover: stack, frontend, prover_backend: proverBackend,
        witness_backend: witnessBackend, sample_kind: isWarmup ? "warmup" : "measured", sample_index: isWarmup ? 0 : index,
        status: "ok", initialization_time_ms: null, witness_time_ms: item.sample.witness, prover_time_ms: item.sample.prove,
        verify_time_ms: null, total_time_ms: item.sample.outer, peak_memory_mib: item.sample.peak,
        proof_size_bytes: item.sample.proof, circuit_size_bytes: item.sample.payload, artifact_size_bytes: item.sample.artifact,
        bundle_size_bytes: item.sample.bundle, constraint_count: null, artifact_version: "input-to-proof-v1",
        source_commit: stack === "provekit_v1" ? "9b2a6f37c67691eab4b0cec6c35e35c520e93285" : circuit.commit,
        package_versions: nativePackages(profile, stack), artifact_hashes: JSON.stringify(hashes), session_id: "",
        non_equivalence_note: `${circuit.note}${stack === "provekit_v1" ? " Native ProveKit exposes witness generation and proving as one integrated timed operation, so witness_time_ms is intentionally blank." : ""}`,
        failure_code: "", failure_detail: "", evidence_path: item.evidence.map((value) => value.path).join(";"),
        timing_mode: mode, input_to_proof_time_ms: item.sample.outer,
      });
    }
  }
  return rows;
}

if (import.meta.main) {
  const targets = (process.env.INPUT_TO_PROOF_EXPORT_TARGETS ?? "mac_chrome").split(",") as Target[];
  const rows = [
    ...(targets.includes("mac_chrome") ? await buildMacRows() : []),
    ...(targets.includes("iphone_se_2022") ? await buildIphoneRows() : []),
    ...(targets.includes("motorola_e15") ? await buildE15Rows() : []),
  ];
  validateRows(rows, expectedSeries(targets));
  const csv = [CSV_COLUMNS.join(","), ...rows.map((row) => CSV_COLUMNS.map((column) => csvValue(row[column])).join(","))].join("\n") + "\n";
  await Bun.write(output, csv);
  console.log(`${output}: ${rows.length} rows, ${expectedSeries(targets).length} series validated`);
}
