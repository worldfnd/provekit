import { describe, expect, test } from "bun:test";
import {
  parseDevice,
  reconstructBenchResults,
  slugify,
  verifyBenchContract,
} from "./android-appium-evidence";

const functionName = "bench_mobile::bench_oprf_verify";
const payload = {
  spec: { name: functionName, iterations: 5, warmup: 1 },
  samples: [11, 12, 13, 14, 15].map((duration_ns) => ({ duration_ns })),
  function: functionName,
  samples_ns: [11, 12, 13, 14, 15],
};

describe("Android Appium evidence", () => {
  test("reconstructs chunked BENCH_JSON with logcat prefixes", () => {
    const json = JSON.stringify(payload);
    const split = Math.floor(json.length / 2);
    const log = [
      "07-26 I/BenchRunner: BENCH_JSON_START",
      `07-26 I/BenchRunner: BENCH_JSON_CHUNK ${json.slice(0, split)}`,
      `07-26 I/BenchRunner: BENCH_JSON_CHUNK ${json.slice(split)}`,
      "07-26 I/BenchRunner: BENCH_JSON_END",
    ].join("\n");
    const results = reconstructBenchResults(log);
    expect(results).toHaveLength(1);
    expect(() => verifyBenchContract(results[0]!, functionName)).not.toThrow();
  });

  test("rejects an incomplete sampling contract", () => {
    const invalid = structuredClone(payload);
    invalid.samples_ns.pop();
    expect(() => verifyBenchContract(invalid, functionName)).toThrow(
      "five positive integer samples_ns",
    );
  });

  test("rejects unterminated evidence", () => {
    expect(() =>
      reconstructBenchResults(
        "I/BenchRunner: BENCH_JSON_START\nI/BenchRunner: BENCH_JSON_CHUNK {}",
      ),
    ).toThrow("ended inside");
  });

  test("parses BrowserStack device labels from the final separator", () => {
    expect(parseDevice("Samsung Galaxy S24-14.0")).toEqual({
      label: "Samsung Galaxy S24-14.0",
      deviceName: "Samsung Galaxy S24",
      osVersion: "14.0",
    });
  });

  test("creates stable filesystem slugs", () => {
    expect(slugify(functionName)).toBe("bench-mobile-bench-oprf-verify");
  });
});
