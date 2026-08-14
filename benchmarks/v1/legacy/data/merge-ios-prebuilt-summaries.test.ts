import { describe, expect, test } from "bun:test";
import { mergeIosPrebuiltSummaries } from "./merge-ios-prebuilt-summaries";

describe("mergeIosPrebuiltSummaries", () => {
  test("merges disjoint Mobench function maps", () => {
    const merged = mergeIosPrebuiltSummaries([
      { path: "a.json", summary: { functions: { a: { value: 1 } } } },
      { path: "b.json", summary: { functions: { b: { value: 2 } } } },
    ]);
    expect(Object.keys(merged.functions)).toEqual(["a", "b"]);
  });

  test("rejects conflicting duplicate function evidence", () => {
    expect(() =>
      mergeIosPrebuiltSummaries([
        { path: "a.json", summary: { functions: { same: { value: 1 } } } },
        { path: "b.json", summary: { functions: { same: { value: 2 } } } },
      ]),
    ).toThrow(/conflicting duplicate/);
  });
});
