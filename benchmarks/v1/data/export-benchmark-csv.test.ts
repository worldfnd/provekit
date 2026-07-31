import { describe, expect, test } from "bun:test";
import {
  ValidationError,
  toCsv,
  validateAttempts,
} from "./export-benchmark-csv";
import {
  CIRCUITS,
  CSV_COLUMNS,
  HARDWARE,
  PROVERS,
  EXPECTED_RUNTIME,
  type AttemptRecord,
} from "./schema";

function base(overrides: Partial<AttemptRecord> = {}): AttemptRecord {
  return {
    campaign_id: "campaign-1",
    attempt_id: "attempt-1",
    recorded_at_utc: "2026-07-29T12:00:00Z",
    hardware: "iphone_se_2022",
    device_model: "iPhone SE 2022",
    os_version: "iOS 15.4",
    abi: "arm64",
    runtime: "ios_native",
    browser: "",
    circuit: "oprf",
    circuit_variant: "oprf_taceo",
    circuit_commit: "1111111111111111111111111111111111111111",
    prover: "provekit_v1",
    frontend: "noir",
    prover_backend: "whir",
    witness_backend: "",
    sample_kind: "measured",
    sample_index: 1,
    status: "ok",
    initialization_time_ms: 0.5,
    witness_time_ms: null,
    prover_time_ms: 12.5,
    verify_time_ms: 1.25,
    total_time_ms: 13.75,
    peak_memory_mib: 42,
    proof_size_bytes: 1024,
    circuit_size_bytes: 2048,
    artifact_size_bytes: 4096,
    bundle_size_bytes: 8192,
    constraint_count: 100,
    artifact_version: "fixture-v1",
    source_commit: "0123456789abcdef0123456789abcdef01234567",
    package_versions: "{\"provekit\":\"1.0.0\"}",
    artifact_hashes: "{\"pkp\":\"sha256:abc\"}",
    session_id: "fixture-session",
    non_equivalence_note: "Closest available circuit; not statement-equivalent.",
    failure_code: "",
    failure_detail: "",
    evidence_path: "evidence/attempt-1.json",
    ...overrides,
  };
}

function completeMatrix(): AttemptRecord[] {
  const records: AttemptRecord[] = [];
  for (const hardware of HARDWARE) {
    for (const circuit of CIRCUITS) {
      for (const prover of PROVERS) {
        for (let index = 0; index <= 5; index++) {
          records.push(
            base({
              attempt_id: `${hardware}-${circuit}-${prover}-${index}`,
              hardware,
              runtime: EXPECTED_RUNTIME[hardware],
              browser: hardware === "macbook_m4" ? "Google Chrome fixture" : "",
              circuit,
              prover,
              frontend: prover === "circom_groth16" ? "circom" : "noir",
              prover_backend:
                prover === "provekit_v1"
                  ? "whir"
                  : prover === "noir_barretenberg"
                    ? "ultra_honk"
                    : "rapidsnark",
              witness_backend: prover === "circom_groth16" ? "witnesscalc_adapter" : "",
              witness_time_ms: prover === "circom_groth16" ? 2 : null,
              sample_kind: index === 0 ? "warmup" : "measured",
              sample_index: index,
              prover_time_ms: 12.5,
              total_time_ms: prover === "circom_groth16" ? 14.5 : 12.5,
            }),
          );
        }
      }
    }
  }
  return records;
}

describe("validateAttempts", () => {
  test("accepts the complete 27-cell matrix with one warmup and five samples", () => {
    expect(validateAttempts(completeMatrix())).toHaveLength(27 * 6);
  });

  test("accepts one explicit gap row in place of samples", () => {
    const records = completeMatrix().filter(
      (record) =>
        !(
          record.hardware === "motorola_e15" &&
          record.circuit === "passport" &&
          record.prover === "circom_groth16"
        ),
    );
    records.push(
      base({
        attempt_id: "moto-passport-circom-gap",
        hardware: "motorola_e15",
        runtime: "android_native",
        circuit: "passport",
        prover: "circom_groth16",
        frontend: "circom",
        prover_backend: "rapidsnark",
        witness_backend: "witnesscalc_adapter",
        sample_kind: "gap",
        sample_index: null,
        status: "unsupported",
        initialization_time_ms: null,
        witness_time_ms: null,
        prover_time_ms: null,
        verify_time_ms: null,
        total_time_ms: null,
        peak_memory_mib: null,
        proof_size_bytes: null,
        circuit_size_bytes: null,
        artifact_size_bytes: null,
        bundle_size_bytes: null,
        constraint_count: null,
        failure_code: "unsupported_abi",
        failure_detail: "Rapidsnark does not publish an armv7 Android library.",
      }),
    );
    expect(validateAttempts(records)).toHaveLength(26 * 6 + 1);
  });

  test("rejects metrics on gap records", () => {
    expect(() =>
      validateAttempts(
        [
          base({
            sample_kind: "gap",
            sample_index: null,
            status: "runtime_failed",
            initialization_time_ms: null,
            prover_time_ms: 0,
            total_time_ms: null,
            verify_time_ms: null,
            peak_memory_mib: null,
            proof_size_bytes: null,
            circuit_size_bytes: null,
            artifact_size_bytes: null,
            bundle_size_bytes: null,
            constraint_count: null,
            failure_code: "crash",
            failure_detail: "SIGSEGV",
          }),
        ],
        false,
      ),
    ).toThrow(ValidationError);
  });

  test("rejects duplicate logical samples and duplicate attempt ids", () => {
    const record = base();
    expect(() => validateAttempts([record, { ...record }], false)).toThrow(
      /duplicate attempt_id/,
    );
  });

  test("rejects a native runtime assigned to the Mac browser target", () => {
    expect(() =>
      validateAttempts(
        [base({ hardware: "macbook_m4", runtime: "ios_native" })],
        false,
      ),
    ).toThrow(/does not match macbook_m4/);
  });

  test("rejects incomplete successful cells in full-matrix mode", () => {
    expect(() => validateAttempts([base()])).toThrow(/requires 1 warmup/);
  });

  test("accepts an attested native warmup with unavailable timing", () => {
    expect(
      validateAttempts(
        [
          base({
            sample_kind: "warmup",
            sample_index: 0,
            prover_time_ms: null,
            total_time_ms: null,
          }),
        ],
        false,
      ),
    ).toHaveLength(1);
  });

  test("rejects a partially populated warmup timing pair", () => {
    expect(() =>
      validateAttempts(
        [
          base({
            sample_kind: "warmup",
            sample_index: 0,
            prover_time_ms: null,
            total_time_ms: 12,
          }),
        ],
        false,
      ),
    ).toThrow(/must provide both/);
  });

  test("rejects a measured success missing any campaign headline metric", () => {
    for (const missing of [
      "artifact_size_bytes",
      "proof_size_bytes",
      "peak_memory_mib",
    ] as const) {
      expect(() =>
        validateAttempts([base({ [missing]: null })], false),
      ).toThrow(/require proving payload size, proof size, and peak process memory/);
    }
  });

  test("accepts separately named variants inside one comparison cell", () => {
    const records = completeMatrix();
    const firstVariant = records.filter(
      (record) =>
        record.hardware === "macbook_m4" &&
        record.circuit === "oprf" &&
        record.prover === "circom_groth16",
    );
    records.push(
      ...firstVariant.map((record) => ({
        ...record,
        attempt_id: `${record.attempt_id}-nullifier`,
        circuit_variant: "world_id_protocol_nullifier",
      })),
    );
    expect(validateAttempts(records)).toHaveLength(27 * 6 + 6);
  });
});

describe("toCsv", () => {
  test("uses canonical columns, blank nulls, and RFC 4180 escaping", () => {
    const record = base({
      failure_detail: "",
      non_equivalence_note: 'Closest match, not "equivalent".',
    });
    const csv = toCsv([record]);
    expect(csv.split("\n")[0]).toBe(CSV_COLUMNS.join(","));
    expect(csv).toContain(",,12.5");
    expect(csv).toContain('"Closest match, not ""equivalent""."');
  });
});
