#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { mkdtemp, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

type Platform = "ios" | "android";
type Asset = { path: string; bytes: number; sha256: string };
type RuntimeManifest = { platform: Platform; assets: Asset[] };

function parseOptions(args: string[]) {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag?.startsWith("--") || !value) {
      throw new Error(
        "usage: validate-barretenberg-mobile-apps.ts --ipa <path> " +
          "--aab <path> --ios-package <directory> " +
          "--android-package <directory> --output <path>",
      );
    }
    values.set(flag.slice(2), value);
  }
  for (const name of [
    "ipa",
    "aab",
    "ios-package",
    "android-package",
    "output",
  ]) {
    if (!values.has(name)) throw new Error(`--${name} is required`);
  }
  return Object.fromEntries(
    [...values].map(([key, value]) => [key, resolve(value)]),
  ) as Record<string, string>;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fileIdentity(path: string) {
  const bytes = new Uint8Array(await Bun.file(path).arrayBuffer());
  return { bytes: bytes.length, sha256: sha256(bytes) };
}

function archiveEntry(archive: string, entry: string): Uint8Array {
  const result = Bun.spawnSync(["unzip", "-p", archive, entry]);
  if (result.exitCode !== 0 || result.stdout.length === 0) {
    throw new Error(`missing archive entry ${entry}`);
  }
  return result.stdout;
}

function encodedResourceName(path: string): string {
  let encoded = path.replaceAll("/", "_").replaceAll(".", "_").replaceAll("-", "_");
  while (encoded.includes("__")) encoded = encoded.replaceAll("__", "_");
  return `libmobench_bb_v087_${encoded}.so`;
}

async function validateRuntime(
  platform: Platform,
  archive: string,
  packageRoot: string,
) {
  const manifestPath = join(packageRoot, "runtime-package-manifest.json");
  const manifest = (await Bun.file(manifestPath).json()) as RuntimeManifest;
  if (manifest.platform !== platform) {
    throw new Error(`${platform} runtime manifest platform mismatch`);
  }
  const manifestIdentity = await fileIdentity(manifestPath);
  const inputs = [
    {
      path: "runtime-package-manifest.json",
      ...manifestIdentity,
    },
    ...manifest.assets,
  ];
  const prefix =
    platform === "android"
      ? "base/lib/arm64-v8a/"
      : "Payload/BenchRunner.app/";
  const assets = inputs.map((asset) => {
    const entry = prefix + encodedResourceName(asset.path);
    const bytes = archiveEntry(archive, entry);
    if (bytes.length !== asset.bytes || sha256(bytes) !== asset.sha256) {
      throw new Error(`${platform} embedded asset mismatch: ${asset.path}`);
    }
    return {
      path: asset.path,
      archive_entry: entry,
      bytes: asset.bytes,
      sha256: asset.sha256,
    };
  });
  return {
    manifest_sha256: manifestIdentity.sha256,
    asset_count: assets.length,
    assets,
  };
}

const options = parseOptions(Bun.argv.slice(2));
const ipa = options.ipa;
const aab = options.aab;
const iosRuntime = await validateRuntime("ios", ipa, options["ios-package"]);
const androidRuntime = await validateRuntime(
  "android",
  aab,
  options["android-package"],
);

const scratch = await mkdtemp(join(tmpdir(), "provekit-bb-v087-apps."));
const iosExecutable = join(scratch, "BenchRunner");
const androidLibrary = join(scratch, "libprovekit_v1_barretenberg_mobile.so");
await writeFile(
  iosExecutable,
  archiveEntry(ipa, "Payload/BenchRunner.app/BenchRunner"),
);
await writeFile(
  androidLibrary,
  archiveEntry(
    aab,
    "base/lib/arm64-v8a/libprovekit_v1_barretenberg_mobile.so",
  ),
);
const iosArch = Bun.spawnSync(["lipo", iosExecutable, "-archs"]);
const androidArch = Bun.spawnSync(["file", androidLibrary]);
const iosArchitecture = iosArch.stdout.toString().trim();
const androidArchitecture = androidArch.stdout.toString().trim();
if (iosArch.exitCode !== 0 || iosArchitecture !== "arm64") {
  throw new Error(`unexpected IPA architecture: ${iosArchitecture}`);
}
if (
  androidArch.exitCode !== 0 ||
  !androidArchitecture.includes("ELF 64-bit") ||
  !androidArchitecture.includes("ARM aarch64")
) {
  throw new Error(`unexpected AAB architecture: ${androidArchitecture}`);
}

const evidence = {
  schema_version: 1,
  campaign: "provekit-v1",
  backend: "barretenberg",
  backend_version: "0.87.0",
  noir_version: "1.0.0-beta.11",
  upstream_commit: "9081b0ed38c43c120afb7c80f8f6cd418ca5ad70",
  source_sha: "13044531f0f38e02ed19fcbd9b26202b8ba5a962",
  status: "release_apps_payload_validated_not_device_measured",
  ios: {
    artifact: await fileIdentity(ipa),
    executable_architecture: iosArchitecture,
    runtime: iosRuntime,
  },
  android: {
    artifact: await fileIdentity(aab),
    library_architecture: androidArchitecture.replace(`${scratch}/`, ""),
    min_api: 28,
    runtime: androidRuntime,
  },
};
await Bun.write(options.output, `${JSON.stringify(evidence, null, 2)}\n`);
console.log(options.output);
