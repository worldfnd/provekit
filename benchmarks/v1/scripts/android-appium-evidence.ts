import { createHash } from "node:crypto";
import { basename, dirname, resolve } from "node:path";

export type JsonObject = Record<string, unknown>;

export interface BenchResult extends JsonObject {
  function: string;
  spec: {
    name: string;
    iterations: number;
    warmup: number;
  };
  samples: Array<{ duration_ns: number } & JsonObject>;
  samples_ns: number[];
}

export interface AabEntry {
  function: string;
  source_apk: {
    path: string;
    sha256: string;
  };
  release_aab: {
    path: string;
    sha256: string;
    bytes: number;
  };
  embedded_native_library: {
    archive_path: string;
    sha256: string;
  };
  embedded_bench_spec: {
    archive_path: string;
    sha256: string;
  };
  build_profile: "release";
  signed: boolean;
}

export interface AabManifest {
  schema: "provekit.android-release-aabs.v1";
  source_sha: string;
  warmup: 1;
  iterations: 5;
  entries: AabEntry[];
}

export function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

export function isSourceSha(value: unknown): value is string {
  return (
    typeof value === "string" &&
    (/^[0-9a-f]{40}$/.test(value) || /^[0-9a-f]{64}$/.test(value))
  );
}

export async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  const file = Bun.file(path);
  if (!(await file.exists())) throw new Error(`file does not exist: ${path}`);
  for await (const chunk of file.stream()) hash.update(chunk);
  return hash.digest("hex");
}

export function slugify(value: string): string {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 96);
  if (!slug) throw new Error(`cannot derive a safe slug from ${value}`);
  return slug;
}

export function parseDevice(value: string): {
  label: string;
  deviceName: string;
  osVersion: string;
} {
  const separator = value.lastIndexOf("-");
  if (separator <= 0 || separator === value.length - 1) {
    throw new Error(
      `device must use BrowserStack's "Device Name-OS.Version" form: ${value}`,
    );
  }
  return {
    label: value,
    deviceName: value.slice(0, separator),
    osVersion: value.slice(separator + 1),
  };
}

export function reconstructBenchResults(deviceLog: string): BenchResult[] {
  const results: BenchResult[] = [];
  let chunks: string[] | undefined;
  for (const line of deviceLog.split(/\r?\n/)) {
    if (line.includes("BENCH_JSON_START")) {
      chunks = [];
      continue;
    }
    const marker = "BENCH_JSON_CHUNK ";
    const markerOffset = line.indexOf(marker);
    if (markerOffset >= 0 && chunks) {
      chunks.push(line.slice(markerOffset + marker.length));
      continue;
    }
    if (line.includes("BENCH_JSON_END") && chunks) {
      const json = chunks.join("");
      chunks = undefined;
      let parsed: unknown;
      try {
        parsed = JSON.parse(json);
      } catch (error) {
        throw new Error(
          `device log contains malformed BENCH_JSON: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("BENCH_JSON payload must be an object");
      }
      results.push(parsed as BenchResult);
    }
  }
  if (chunks) throw new Error("device log ended inside a BENCH_JSON payload");
  return results;
}

export function verifyBenchContract(
  result: BenchResult,
  expectedFunction: string,
): void {
  if (result.function !== expectedFunction) {
    throw new Error(
      `BENCH_JSON function mismatch: ${String(result.function)} != ${expectedFunction}`,
    );
  }
  if (
    !result.spec ||
    result.spec.name !== expectedFunction ||
    result.spec.warmup !== 1 ||
    result.spec.iterations !== 5
  ) {
    throw new Error(
      `BENCH_JSON contract mismatch for ${expectedFunction}; expected warmup=1 iterations=5`,
    );
  }
  if (!Array.isArray(result.samples) || result.samples.length !== 5) {
    throw new Error(
      `BENCH_JSON for ${expectedFunction} must contain five samples`,
    );
  }
  if (
    !Array.isArray(result.samples_ns) ||
    result.samples_ns.length !== 5 ||
    result.samples_ns.some(
      (sample) => !Number.isSafeInteger(sample) || sample <= 0,
    )
  ) {
    throw new Error(
      `BENCH_JSON for ${expectedFunction} must contain five positive integer samples_ns`,
    );
  }
  for (let index = 0; index < 5; index += 1) {
    const duration = result.samples[index]?.duration_ns;
    if (duration !== result.samples_ns[index]) {
      throw new Error(
        `BENCH_JSON sample ${index} does not match samples_ns for ${expectedFunction}`,
      );
    }
  }
}

function assertObject(
  value: unknown,
  description: string,
): asserts value is JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
}

export async function loadAndVerifyAabManifest(
  manifestPath: string,
): Promise<AabManifest> {
  const absoluteManifest = resolve(manifestPath);
  let parsed: unknown;
  try {
    parsed = await Bun.file(absoluteManifest).json();
  } catch (error) {
    throw new Error(
      `could not read AAB manifest ${absoluteManifest}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  assertObject(parsed, "AAB manifest");
  if (parsed.schema !== "provekit.android-release-aabs.v1") {
    throw new Error(`unsupported AAB manifest schema: ${String(parsed.schema)}`);
  }
  if (!isSourceSha(parsed.source_sha)) {
    throw new Error("AAB manifest source_sha must be 40 or 64 lowercase hex");
  }
  if (parsed.warmup !== 1 || parsed.iterations !== 5) {
    throw new Error("AAB manifest must declare warmup=1 and iterations=5");
  }
  if (!Array.isArray(parsed.entries) || parsed.entries.length === 0) {
    throw new Error("AAB manifest entries must be a non-empty array");
  }
  const seen = new Set<string>();
  for (const [index, rawEntry] of parsed.entries.entries()) {
    assertObject(rawEntry, `AAB manifest entry ${index}`);
    if (
      typeof rawEntry.function !== "string" ||
      rawEntry.function.length === 0 ||
      seen.has(rawEntry.function)
    ) {
      throw new Error(`entry ${index} has an invalid or duplicate function`);
    }
    seen.add(rawEntry.function);
    if (rawEntry.build_profile !== "release") {
      throw new Error(`entry ${index} is not a release build`);
    }
    if (rawEntry.signed !== true) {
      throw new Error(`entry ${index} AAB is not signed`);
    }
    assertObject(rawEntry.release_aab, `entry ${index} release_aab`);
    if (
      typeof rawEntry.release_aab.path !== "string" ||
      !isSha256(rawEntry.release_aab.sha256) ||
      !Number.isSafeInteger(rawEntry.release_aab.bytes) ||
      (rawEntry.release_aab.bytes as number) <= 0
    ) {
      throw new Error(`entry ${index} has invalid release_aab metadata`);
    }
    const aabPath = resolve(
      dirname(absoluteManifest),
      rawEntry.release_aab.path,
    );
    const actualHash = await sha256File(aabPath);
    if (actualHash !== rawEntry.release_aab.sha256) {
      throw new Error(
        `entry ${index} AAB hash mismatch for ${basename(aabPath)}`,
      );
    }
    if (Bun.file(aabPath).size !== rawEntry.release_aab.bytes) {
      throw new Error(
        `entry ${index} AAB size mismatch for ${basename(aabPath)}`,
      );
    }
    rawEntry.release_aab.path = aabPath;
  }
  return parsed as unknown as AabManifest;
}

export async function writeJsonAtomic(
  path: string,
  value: unknown,
): Promise<void> {
  const temporary = `${path}.tmp-${process.pid}`;
  await Bun.write(temporary, `${JSON.stringify(value, null, 2)}\n`);
  await Bun.$`mv ${temporary} ${path}`.quiet();
}

