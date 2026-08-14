#!/usr/bin/env bun

import { resolve } from "node:path";
import { validateAttempts } from "./export-benchmark-csv";
import type { AttemptRecord, Circuit, Prover, Status } from "./schema";

interface DeviceIdentity {
  model?: string;
  os?: string;
  abi?: string;
  zygote?: string;
}

interface GapDefinition {
  circuit: Circuit;
  variant: string;
  circuitCommit: string;
  prover: Prover;
  proverBackend: string;
  witnessBackend: string;
  status: Exclude<Status, "ok">;
  failureCode: string;
  failureDetail: string;
  evidencePath: string;
}

const WORLD_ID = "85aeeef539961cae5a63de794997b507a5975717";
const SELF = "15b167e3543a9dff1dbb16fcf71a45fe4625cf9e";
const WEBAUTHN_CIRCOM = "0fb5b4aa1398281c2fd3dbe14db147e05b61f201";
const TACEO = "808f3c795b57963dd58ef282ccd61022ef39c285";

export function generateE15NativeGaps(
  device: DeviceIdentity,
  options: {
    campaignId: string;
    sourceCommit: string;
    recordedAtUtc: string;
    noirEvidencePath: string;
    circomEvidencePath: string;
  },
): AttemptRecord[] {
  if (device.abi !== "armeabi-v7a" || device.zygote !== "zygote32") {
    throw new Error(
      `E15 gaps require the attested 32-bit target, found ${device.abi}/${device.zygote}`,
    );
  }

  const armv7Noir =
    "Mopro 0.3.7's Barretenberg/Noir backend does not provide a qualified " +
    "armeabi-v7a lane for this 32-bit userspace; no browser timing was substituted.";
  const arkworksNotQualified =
    "Rapidsnark is not available for the E15's armeabi-v7a userspace, and the " +
    "Mopro Arkworks plus rust-witness fallback did not produce a qualified exact-circuit " +
    "armv7 bundle with proof verification, tamper rejection, and 1+5 samples.";

  const gaps: GapDefinition[] = [
    {
      circuit: "passport",
      variant: "passport_complete_age_check",
      circuitCommit: options.sourceCommit,
      prover: "noir_barretenberg",
      proverBackend: "barretenberg-ultrahonk-native",
      witnessBackend: "",
      status: "runtime_failed",
      failureCode: "beta19_witness_exact_division",
      failureDetail:
        "The mechanical Noir beta.19 Passport port fails during RSA witness solving " +
        "in noir-bignum exact division before a device build can be qualified.",
      evidencePath: options.noirEvidencePath,
    },
    {
      circuit: "webauthn",
      variant: "webauthn_assertion",
      circuitCommit: WORLD_ID,
      prover: "noir_barretenberg",
      proverBackend: "barretenberg-ultrahonk-native",
      witnessBackend: "",
      status: "unsupported",
      failureCode: "mopro_noir_armv7_unsupported",
      failureDetail: armv7Noir,
      evidencePath: options.circomEvidencePath,
    },
    {
      circuit: "oprf",
      variant: "oprf_taceo",
      circuitCommit: TACEO,
      prover: "noir_barretenberg",
      proverBackend: "barretenberg-ultrahonk-native",
      witnessBackend: "",
      status: "unsupported",
      failureCode: "mopro_noir_armv7_unsupported",
      failureDetail: armv7Noir,
      evidencePath: options.circomEvidencePath,
    },
    {
      circuit: "passport",
      variant: "self_register_and_vc_and_disclose",
      circuitCommit: SELF,
      prover: "circom_groth16",
      proverBackend: "arkworks-groth16-native-armv7-unqualified",
      witnessBackend: "rust-witness-armv7-unqualified",
      status: "not_run",
      failureCode: "arkworks_armv7_not_qualified",
      failureDetail: arkworksNotQualified,
      evidencePath: options.circomEvidencePath,
    },
    {
      circuit: "webauthn",
      variant: "privacy_ethereum_webauthn",
      circuitCommit: WEBAUTHN_CIRCOM,
      prover: "circom_groth16",
      proverBackend: "arkworks-groth16-native-armv7-unqualified",
      witnessBackend: "rust-witness-armv7-unqualified",
      status: "not_run",
      failureCode: "arkworks_armv7_not_qualified",
      failureDetail: arkworksNotQualified,
      evidencePath: options.circomEvidencePath,
    },
    {
      circuit: "oprf",
      variant: "world_id_protocol_query_and_nullifier",
      circuitCommit: WORLD_ID,
      prover: "circom_groth16",
      proverBackend: "arkworks-groth16-native-armv7-unqualified",
      witnessBackend: "rust-witness-armv7-unqualified",
      status: "not_run",
      failureCode: "arkworks_armv7_not_qualified",
      failureDetail: arkworksNotQualified,
      evidencePath: options.circomEvidencePath,
    },
  ];

  const common = {
    campaign_id: options.campaignId,
    recorded_at_utc: options.recordedAtUtc,
    hardware: "motorola_e15" as const,
    device_model: device.model ?? "moto e15",
    os_version: `Android ${device.os ?? "14"}`,
    abi: device.abi,
    runtime: "android_native" as const,
    browser: "",
    frontend: "noir",
    sample_kind: "gap" as const,
    sample_index: null,
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
    source_commit: options.sourceCommit,
    artifact_hashes: JSON.stringify({}),
    session_id: "",
    non_equivalence_note:
      "Closest available counterpart only; proof statements and implementation details are not equivalent.",
  };

  const records = gaps.map((gap): AttemptRecord => ({
    ...common,
    attempt_id: `motorola-e15-${gap.prover}-${gap.variant}-gap`,
    circuit: gap.circuit,
    circuit_variant: gap.variant,
    circuit_commit: gap.circuitCommit,
    prover: gap.prover,
    frontend: gap.prover === "circom_groth16" ? "circom" : "noir",
    prover_backend: gap.proverBackend,
    witness_backend: gap.witnessBackend,
    status: gap.status,
    artifact_version:
      gap.prover === "circom_groth16"
        ? "mopro-0.3.7-circom-prover-0.1.4-rust-witness-0.1"
        : "noir-v1.0.0-beta.19-barretenberg-rs-4.2.0-aztecnr-rc.2",
    package_versions:
      gap.prover === "circom_groth16"
        ? JSON.stringify({
            mopro: "0.3.7",
            circom_prover: "0.1.4",
            rust_witness: "0.1",
          })
        : JSON.stringify({
            mopro: "0.3.7",
            noir: "1.0.0-beta.19",
            barretenberg_rs: "4.2.0-aztecnr-rc.2",
          }),
    failure_code: gap.failureCode,
    failure_detail: gap.failureDetail,
    evidence_path: resolve(gap.evidencePath),
  }));
  return validateAttempts(records, false);
}

if (import.meta.main) {
  const [
    devicePath,
    outputPath,
    sourceCommit,
    circomEvidencePath = devicePath,
    noirEvidencePath = devicePath,
  ] = process.argv.slice(2);
  if (
    !devicePath ||
    !outputPath ||
    !sourceCommit ||
    !/^[0-9a-f]{40}$/.test(sourceCommit)
  ) {
    console.error(
      "usage: bun generate-e15-native-gaps.ts <device.json> <attempts.json> " +
        "<source-commit> [circom-evidence-path] [noir-evidence-path]",
    );
    process.exit(2);
  }
  const device = (await Bun.file(devicePath).json()) as DeviceIdentity;
  const records = generateE15NativeGaps(device, {
    campaignId: process.env.CAMPAIGN_ID ?? "provekit-v1-cross-device-20260730",
    sourceCommit,
    recordedAtUtc: new Date().toISOString(),
    noirEvidencePath,
    circomEvidencePath,
  });
  await Bun.write(outputPath, `${JSON.stringify(records, null, 2)}\n`);
  console.log(`wrote ${records.length} E15 native gap records to ${outputPath}`);
}
