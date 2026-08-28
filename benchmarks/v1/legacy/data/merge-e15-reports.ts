#!/usr/bin/env bun

import { resolve } from "node:path";

interface E15Report {
  schema_version: number;
  campaign_id: string;
  sampling: { warmup: number; measured: number; sequential: boolean };
  device: { abi?: string; zygote?: string; [key: string]: unknown };
  apk: {
    path?: string;
    sha256: string;
    bytes?: number;
    [key: string]: unknown;
  };
  results: Array<{
    workload: string;
    apk?: E15Report["apk"];
    [key: string]: unknown;
  }>;
}

const workloadOrder = ["oprf", "webauthn", "passport"];

export function mergeE15Reports(
  inputs: Array<{ path: string; report: E15Report; sha256?: string }>,
  campaignId?: string,
) {
  const first = inputs[0];
  if (!first) throw new Error("at least one E15 report is required");
  const expected = {
    sampling: JSON.stringify(first.report.sampling),
    abi: first.report.device.abi,
    zygote: first.report.device.zygote,
  };
  const results = new Map<string, E15Report["results"][number]>();
  for (const input of inputs) {
    const actual = {
      sampling: JSON.stringify(input.report.sampling),
      abi: input.report.device.abi,
      zygote: input.report.device.zygote,
    };
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(`${input.path}: incompatible E15 report identity`);
    }
    if (!campaignId && input.report.campaign_id !== first.report.campaign_id) {
      throw new Error(`${input.path}: incompatible E15 report campaign`);
    }
    for (const result of input.report.results) {
      if (!workloadOrder.includes(result.workload)) {
        throw new Error(
          `${input.path}: unknown E15 workload ${result.workload}`,
        );
      }
      results.set(result.workload, { ...result, apk: input.report.apk });
    }
  }
  return {
    ...first.report,
    campaign_id: campaignId ?? first.report.campaign_id,
    generated_at_utc: new Date().toISOString(),
    provenance: inputs.map((input) => ({
      path: resolve(input.path),
      sha256: input.sha256 ?? "",
    })),
    results: workloadOrder
      .map((workload) => results.get(workload))
      .filter((result): result is E15Report["results"][number] =>
        Boolean(result),
      ),
  };
}

if (import.meta.main) {
  const [outputPath, ...inputPaths] = process.argv.slice(2);
  if (!outputPath || inputPaths.length === 0) {
    console.error(
      "usage: bun merge-e15-reports.ts <output.json> <results.json> [results.json ...]",
    );
    process.exit(2);
  }
  const inputs = await Promise.all(
    inputPaths.map(async (path) => {
      const bytes = await Bun.file(path).bytes();
      return {
        path,
        report: JSON.parse(new TextDecoder().decode(bytes)) as E15Report,
        sha256: new Bun.CryptoHasher("sha256").update(bytes).digest("hex"),
      };
    }),
  );
  const merged = mergeE15Reports(inputs, process.env.CAMPAIGN_ID);
  await Bun.write(outputPath, `${JSON.stringify(merged, null, 2)}\n`);
  console.log(
    `wrote ${merged.results.length} E15 workload results to ${outputPath}`,
  );
}
