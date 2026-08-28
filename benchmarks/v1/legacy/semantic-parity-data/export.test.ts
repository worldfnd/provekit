import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CSV_COLUMNS, EXPECTED_RUNTIME, PROFILES, STACKS, TARGETS, cellId, expectedCellIds, type ParitySample } from "./schema";
import { exportCampaign, toCsv, validate } from "./export";

function row(overrides: Partial<ParitySample> = {}): ParitySample {
  return {
    campaign_id: "semantic-parity-v1-20260731", semantic_profile: "passport_p1",
    cell_id: "passport_p1__mac_chrome__provekit_v1", target: "mac_chrome",
    device_model: "MacBook Pro", os_version: "macOS", abi: "arm64", runtime: "browser_wasm",
    browser: "Chrome", stack: "provekit_v1", frontend: "noir", prover_backend: "whir",
    witness_backend: "noir_js", sample_kind: "measured", sample_index: 1, status: "ok",
    prove_time_ms: 1, proof_size_bytes: 2, proving_payload_size_bytes: 3, process_peak_memory_kib: 4,
    valid_proof_accepted: true, tampered_proof_rejected: true, constraint_count: null,
    source_commits: "{}", package_versions: "{}", artifact_hashes: "{}", evidence_path: "x",
    evidence_sha256: "a".repeat(64), session_id: "", failure_code: "", failure_detail: "",
    semantic_equivalence_note: "Matched semantic profile.", ...overrides,
  };
}

describe("semantic parity export", () => {
  test("freezes the 27-cell semantic matrix and stable CSV schema", () => {
    expect(expectedCellIds()).toHaveLength(27);
    expect(new Set(expectedCellIds()).size).toBe(27);
    expect(toCsv([]).trim()).toBe(CSV_COLUMNS.join(","));
  });

  test("emits the exact legacy benchmark-samples.csv schema and metric units", async () => {
    const legacyHeader = (await Bun.file(new URL("../legacy/data/benchmark-samples.csv", import.meta.url)).text()).split("\n", 1)[0];
    expect(CSV_COLUMNS.join(",")).toBe(legacyHeader);
    const output = toCsv([row({ prove_time_ms: 12.5, proof_size_bytes: 42,
      proving_payload_size_bytes: 9000, process_peak_memory_kib: 2048 })]);
    const values = output.trim().split("\n")[1].split(",");
    const mapped = Object.fromEntries(CSV_COLUMNS.map((column, index) => [column, values[index]]));
    expect(mapped.prover_time_ms).toBe("12.5");
    expect(mapped.proof_size_bytes).toBe("42");
    expect(mapped.circuit_size_bytes).toBe("9000");
    expect(mapped.peak_memory_mib).toBe("2");
  });

  test("ingests seven qualified Mac cells and six frozen WebAuthn cells", async () => {
    const rows = await exportCampaign();
    expect(rows).toHaveLength(78);
    expect(new Set(rows.map((r) => r.cell_id)).size).toBe(13);
    for (const id of new Set(rows.map((r) => r.cell_id))) {
      const cell = rows.filter((r) => r.cell_id === id);
      expect(cell.filter((r) => r.sample_kind === "warmup")).toHaveLength(1);
      expect(cell.filter((r) => r.sample_kind === "measured")).toHaveLength(5);
    }
  });

  test("preserves all four historical WebAuthn metrics and corrected Circom payload provenance", async () => {
    const rows = (await exportCampaign()).filter((candidate) => candidate.semantic_profile === "webauthn_closest_analogue");
    expect(rows).toHaveLength(42);
    const historical = rows.filter((candidate) => candidate.stack !== "provekit_v1");
    expect(historical).toHaveLength(36);
    for (const candidate of historical.filter((candidate) => candidate.sample_kind === "measured")) {
      expect(candidate.prove_time_ms).toBeGreaterThan(0);
      expect(candidate.proof_size_bytes).toBeGreaterThan(0);
      expect(candidate.proving_payload_size_bytes).toBeGreaterThan(0);
      expect(candidate.process_peak_memory_kib).toBeGreaterThan(0);
      expect(candidate.semantic_equivalence_note).toContain("Historical note verbatim:");
    }
    const macCircom = historical.find((candidate) => candidate.target === "mac_chrome" && candidate.stack === "circom_groth16" && candidate.sample_kind === "measured")!;
    expect(macCircom.proving_payload_size_bytes).toBe(1_753_618_376);
    expect(macCircom.semantic_equivalence_note).toContain("20,470,384-byte WASM");
    const e15Circom = historical.find((candidate) => candidate.target === "motorola_e15" && candidate.stack === "circom_groth16" && candidate.sample_kind === "measured")!;
    expect(e15Circom.proving_payload_size_bytes).toBe(1_842_364_184);
    expect(e15Circom.semantic_equivalence_note).toContain("109,218,412-byte frozen witness library");
    const iphoneCircom = historical.find((candidate) => candidate.target === "iphone_se_2022" && candidate.stack === "circom_groth16" && candidate.sample_kind === "measured")!;
    expect(iphoneCircom.semantic_equivalence_note).toContain("asset-size estimate: zkey plus frozen WTNS");
    const expectedPayloads = new Map([
      [cellId("webauthn_closest_analogue", "mac_chrome", "noir_barretenberg"), 74_003_114],
      [cellId("webauthn_closest_analogue", "iphone_se_2022", "noir_barretenberg"), 271_478_529],
      [cellId("webauthn_closest_analogue", "motorola_e15", "noir_barretenberg"), 271_478_529],
    ]);
    for (const [id, payload] of expectedPayloads) {
      const measured = historical.filter((candidate) => candidate.cell_id === id && candidate.sample_kind === "measured");
      expect(measured).toHaveLength(5);
      expect(new Set(measured.map((candidate) => candidate.proving_payload_size_bytes))).toEqual(new Set([payload]));
      expect(measured[0].semantic_equivalence_note).toContain("Payload correction");
    }
  });

  test("rejects duplicate samples, wrong runtime, wrong profile and blank headline metrics", () => {
    expect(() => validate([row(), row()])).toThrow(/duplicate/);
    expect(() => validate([row({ runtime: "ios_native" })])).toThrow(/runtime separation/);
    expect(() => validate([row({ semantic_profile: "oprf_o2" })])).toThrow(/profile\/cell mismatch/);
    expect(() => validate([row({ proving_payload_size_bytes: null })])).toThrow(/blank\/invalid/);
  });

  test("keeps unavailable metrics blank and requires a structured status", () => {
    const gap = row({ sample_kind: "gap", sample_index: null, status: "unsupported", prove_time_ms: null,
      proof_size_bytes: null, proving_payload_size_bytes: null, process_peak_memory_kib: null,
      valid_proof_accepted: null, tampered_proof_rejected: null, failure_code: "unsupported_abi",
      failure_detail: "No compatible binary exists." });
    expect(validate([gap])).toHaveLength(1);
    expect(() => validate([{ ...gap, proof_size_bytes: 0 }])).toThrow(/must be blank/);
    expect(() => validate([{ ...gap, failure_code: "" }])).toThrow(/structured failure/);
    expect(() => validate([row(), gap])).toThrow(/duplicate cell evidence/);
  });

  test("ingests one native structured gap without fabricating metrics", async () => {
    const dir = mkdtempSync(join(tmpdir(), "parity-gap-"));
    const path = join(dir, "gap.json");
    await Bun.write(path, JSON.stringify({
      schema_version: 1, campaign_id: "semantic-parity-v1-20260731", semantic_profile: "oprf_o2",
      target: "motorola_e15", stack: "noir_barretenberg",
      device: { model: "Motorola E15", os_version: "Android", abi: "armeabi-v7a" },
      runtime: "android_native", frontend: "noir", prover_backend: "barretenberg", witness_backend: "noir",
      source_commits: {}, package_versions: {}, artifact_hashes: {}, proving_payload_size_bytes: null,
      process_peak_memory_kib: null, valid_proof_accepted: null, tampered_proof_rejected: null,
      session_id: "adb-session", gap: { status: "unsupported", failure_code: "unsupported_abi",
        failure_detail: "No armv7 backend exists.", prove_time_ms: null, proof_size_bytes: null },
    }));
    try {
      const rows = await exportCampaign([path]);
      const gap = rows.find((candidate) => candidate.cell_id === "oprf_o2__motorola_e15__noir_barretenberg");
      expect(gap?.sample_kind).toBe("gap");
      expect(gap?.status).toBe("unsupported");
      expect(gap?.prove_time_ms).toBeNull();
      expect(gap?.proving_payload_size_bytes).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("counts explicit gap cells as covered in complete-matrix validation", () => {
    const gaps: ParitySample[] = [];
    for (const semantic_profile of PROFILES) for (const target of TARGETS) for (const stack of STACKS) {
      gaps.push(row({ semantic_profile, target, stack, cell_id: cellId(semantic_profile, target, stack),
        runtime: EXPECTED_RUNTIME[target], browser: target === "mac_chrome" ? "Chrome" : "",
        sample_kind: "gap", sample_index: null, status: "zero_samples", prove_time_ms: null,
        proof_size_bytes: null, proving_payload_size_bytes: null, process_peak_memory_kib: null,
        valid_proof_accepted: null, tampered_proof_rejected: null, failure_code: "zero_samples",
        failure_detail: "No qualified samples were retained." }));
    }
    expect(validate(gaps, true)).toHaveLength(27);
  });

  test("rejects incomplete successful series and incomplete full matrix", () => {
    expect(() => validate([row()])).toThrow(/requires 1\+5/);
    expect(() => validate([], true)).toThrow(/missing 27 cells/);
  });
});
