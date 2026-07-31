#!/usr/bin/env bun

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const [runnerArg] = process.argv.slice(2);
if (!runnerArg) {
  throw new Error(
    "usage: bun patch-ios-runner-json.ts <BenchRunnerFFI.swift>",
  );
}

const runner = resolve(runnerArg);
const unsafe =
  'jsonReport: "{\\"error\\": true, \\"message\\": \\"\\(escapeJSON(message))\\"}"';
const safe =
  'jsonReport: serializeJSON(["error": true, "message": message])';
const source = await readFile(runner, "utf8");
const occurrences = source.split(unsafe).length - 1;

if (source.includes(safe)) {
  if (occurrences !== 0) {
    throw new Error(`runner contains both JSON error paths: ${runner}`);
  }
  console.log(`Validated JSON-safe error reporting in ${runner}`);
  process.exit(0);
}
if (occurrences !== 1) {
  throw new Error(
    `expected exactly one generated JSON error path in ${runner}, found ${occurrences}`,
  );
}

await writeFile(runner, source.replace(unsafe, safe));
console.log(`Patched JSON-safe error reporting in ${runner}`);
