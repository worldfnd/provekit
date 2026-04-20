import { describe, expect, it } from "vitest";

import { parseSimpleToml } from "../shared/toml-parser.mjs";

describe("parseSimpleToml", () => {
  it("parses section-scoped dotted keys and inline tables", () => {
    const result = parseSimpleToml(`
[person]
name.first = "Ada"
name.last = "Lovelace"
metadata = { role = "mathematician", active = "true" }
`);

    expect(result).toEqual({
      person: {
        name: {
          first: "Ada",
          last: "Lovelace",
        },
        metadata: {
          role: "mathematician",
          active: "true",
        },
      },
    });
  });

  it("parses multiline arrays and arrays of inline tables", () => {
    const result = parseSimpleToml(`
values = [
  "a",
  "b",
  { nested = "c" }
]
entries = [{ key = "one" }, { key = "two" }]
`);

    expect(result).toEqual({
      values: ["a", "b", { nested: "c" }],
      entries: [{ key: "one" }, { key: "two" }],
    });
  });

  it("preserves bare scalars as strings and skips comments/blank lines", () => {
    const result = parseSimpleToml(`
# comment
count = 42
flag = true

[path]
value = '/tmp/demo'
`);

    expect(result).toEqual({
      count: "42",
      flag: "true",
      path: {
        value: "/tmp/demo",
      },
    });
  });
});
