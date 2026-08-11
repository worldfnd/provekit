import { describe, expect, test } from "bun:test";
import {
  orchestrationFailure,
  parseBenchJson,
  parseFailureJson,
} from "./run-e15-provekit";

describe("E15 logcat parsing", () => {
  test("reassembles chunked Mobench JSON in order", () => {
    const log = [
      "1 I BenchRunner: BENCH_JSON_START",
      '2 I BenchRunner: BENCH_JSON_CHUNK {"spec":{"name":"oprf"},',
      '3 I BenchRunner: BENCH_JSON_CHUNK "samples":[{"duration_ns":42}]}',
      "4 I BenchRunner: BENCH_JSON_END",
    ].join("\n");
    expect(parseBenchJson(log)).toEqual({
      spec: { name: "oprf" },
      samples: [{ duration_ns: 42 }],
    });
  });

  test("uses the last complete report when Android launches the activity twice", () => {
    const log = [
      "1 I BenchRunner: BENCH_JSON_START",
      '2 I BenchRunner: BENCH_JSON_CHUNK {"samples":[{"duration_ns":41}]}',
      "3 I BenchRunner: BENCH_JSON_END",
      "4 I BenchRunner: BENCH_JSON_START",
      '5 I BenchRunner: BENCH_JSON_CHUNK {"samples":[{"duration_ns":42}]}',
      "6 I BenchRunner: BENCH_JSON_END",
    ].join("\n");
    expect(parseBenchJson(log)).toEqual({ samples: [{ duration_ns: 42 }] });
  });

  test("extracts the last structured failure", () => {
    const log = [
      '1 I BenchRunner: BENCH_FAILURE_JSON {"kind":"old"}',
      '2 I BenchRunner: BENCH_FAILURE_JSON {"kind":"benchmark_error","message":"panic detail"}',
    ].join("\n");
    expect(parseFailureJson(log)).toEqual({
      kind: "benchmark_error",
      message: "panic detail",
    });
  });

  test("retains a device reboot failure as a structured unmeasured result", () => {
    expect(
      orchestrationFailure(
        "webauthn",
        "bench_mobile::bench_webauthn_assertion_e2e",
        new Error("device did not return"),
        "/evidence/webauthn.orchestration-failure.json",
      ),
    ).toMatchObject({
      workload: "webauthn",
      status: "not_run",
      failure: {
        kind: "device_orchestration_failed",
        message: "device did not return",
      },
    });
  });
});
