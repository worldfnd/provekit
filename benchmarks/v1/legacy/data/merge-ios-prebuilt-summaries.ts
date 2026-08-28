#!/usr/bin/env bun

import { resolve } from "node:path";

interface MobenchSummary {
  functions?: Record<string, unknown>;
}

export function mergeIosPrebuiltSummaries(
  inputs: Array<{ path: string; summary: MobenchSummary; sha256?: string }>,
) {
  const functions: Record<string, unknown> = {};
  for (const input of inputs) {
    if (!input.summary.functions || typeof input.summary.functions !== "object") {
      throw new Error(`${input.path}: missing Mobench functions object`);
    }
    for (const [name, result] of Object.entries(input.summary.functions)) {
      if (name in functions) {
        if (JSON.stringify(functions[name]) !== JSON.stringify(result)) {
          throw new Error(`${name}: conflicting duplicate iOS benchmark result`);
        }
        continue;
      }
      functions[name] = result;
    }
  }
  return {
    schema: "provekit.merged-ios-prebuilt-summaries.v1",
    generated_at_utc: new Date().toISOString(),
    inputs: inputs.map((input) => ({
      path: resolve(input.path),
      sha256: input.sha256 ?? "",
    })),
    functions,
  };
}

if (import.meta.main) {
  const [outputPath, ...inputPaths] = process.argv.slice(2);
  if (!outputPath || inputPaths.length === 0) {
    console.error(
      "usage: bun merge-ios-prebuilt-summaries.ts <output.json> <summary.json> [summary.json ...]",
    );
    process.exit(2);
  }
  const inputs = await Promise.all(
    inputPaths.map(async (path) => {
      const bytes = await Bun.file(path).bytes();
      return {
        path,
        summary: JSON.parse(new TextDecoder().decode(bytes)) as MobenchSummary,
        sha256: new Bun.CryptoHasher("sha256").update(bytes).digest("hex"),
      };
    }),
  );
  const merged = mergeIosPrebuiltSummaries(inputs);
  await Bun.write(outputPath, `${JSON.stringify(merged, null, 2)}\n`);
  console.log(
    `wrote ${Object.keys(merged.functions).length} iOS function results to ${outputPath}`,
  );
}
