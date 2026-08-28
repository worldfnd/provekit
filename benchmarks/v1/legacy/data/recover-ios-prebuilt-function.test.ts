import { describe, expect, test } from "bun:test";
import { extractBenchmarkResult } from "./recover-ios-prebuilt-function";

describe("extractBenchmarkResult", () => {
  test("extracts identical timestamped and raw Mobench JSON", () => {
    const result = {
      function: "crate::bench",
      samples: [1, 2, 3, 4, 5].map((duration_ns) => ({ duration_ns })),
    };
    const json = JSON.stringify(result);
    expect(
      extractBenchmarkResult(
        [`timestamp Runner[1:2] ${json}\n${json}\nordinary Xcode prose`],
        "crate::bench",
      ),
    ).toEqual(result);
  });

  test("rejects conflicting retained results", () => {
    const first = JSON.stringify({
      function: "crate::bench",
      samples: [1, 2, 3, 4, 5],
    });
    const second = JSON.stringify({
      function: "crate::bench",
      samples: [6, 7, 8, 9, 10],
    });
    expect(() =>
      extractBenchmarkResult([`${first}\n${second}`], "crate::bench"),
    ).toThrow(/conflicting benchmark JSON/);
  });
});
