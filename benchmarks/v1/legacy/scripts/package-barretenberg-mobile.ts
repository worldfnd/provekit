#!/usr/bin/env bun

import { mkdir, readdir, copyFile, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, join, relative, resolve } from "node:path";

type Options = {
  platform: "ios" | "android";
  adapterLibrary: string;
  upstreamLibrary: string;
  crs: string;
  output: string;
};

function parseOptions(args: string[]): Options {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag?.startsWith("--") || !value) {
      throw new Error(
        "usage: package-barretenberg-mobile.ts --platform <ios|android> " +
          "--adapter-library <archive> --upstream-library <archive> " +
          "--crs <directory> --output <directory>",
      );
    }
    values.set(flag.slice(2), value);
  }
  const platform = values.get("platform");
  if (platform !== "ios" && platform !== "android") {
    throw new Error("--platform must be ios or android");
  }
  for (const required of [
    "adapter-library",
    "upstream-library",
    "crs",
    "output",
  ]) {
    if (!values.get(required)) throw new Error(`--${required} is required`);
  }
  return {
    platform,
    adapterLibrary: resolve(values.get("adapter-library")!),
    upstreamLibrary: resolve(values.get("upstream-library")!),
    crs: resolve(values.get("crs")!),
    output: resolve(values.get("output")!),
  };
}

async function filesBelow(root: string): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) result.push(...(await filesBelow(path)));
    else if (entry.isFile()) result.push(path);
  }
  return result.sort();
}

async function sha256(path: string): Promise<string> {
  const bytes = await Bun.file(path).arrayBuffer();
  return createHash("sha256").update(new Uint8Array(bytes)).digest("hex");
}

const options = parseOptions(Bun.argv.slice(2));
const benchmarkRoot = resolve(import.meta.dir, "..");
const fixtureRoot = join(benchmarkRoot, "barretenberg", "web", "dist", "assets");
const workloads = [
  "oprf_taceo",
  "webauthn_assertion",
  "passport_complete_age_check",
];
const requiredFixtureNames = [
  "circuit.json",
  "witness.gz",
  "public-inputs.json",
  "proof.bin",
];

await mkdir(options.output, { recursive: true });
const inputs: Array<{ source: string; destination: string; role: string }> = [
  {
    source: options.adapterLibrary,
    destination: join("lib", basename(options.adapterLibrary)),
    role: "native-adapter-library",
  },
  {
    source: options.upstreamLibrary,
    destination: join("lib", basename(options.upstreamLibrary)),
    role: "native-upstream-library",
  },
];
for (const source of await filesBelow(options.crs)) {
  inputs.push({
    source,
    destination: join("crs", relative(options.crs, source)),
    role: "crs",
  });
}
for (const workload of workloads) {
  for (const name of requiredFixtureNames) {
    inputs.push({
      source: join(fixtureRoot, workload, name),
      destination: join("fixtures", workload, name),
      role: `fixture:${workload}`,
    });
  }
}

const assets = [];
for (const input of inputs) {
  const metadata = await stat(input.source);
  if (!metadata.isFile()) throw new Error(`not a file: ${input.source}`);
  const destination = join(options.output, input.destination);
  await mkdir(resolve(destination, ".."), { recursive: true });
  await copyFile(input.source, destination);
  assets.push({
    path: input.destination,
    role: input.role,
    bytes: metadata.size,
    sha256: await sha256(destination),
  });
}
for (const workload of workloads) {
  const circuit = (await Bun.file(
    join(fixtureRoot, workload, "circuit.json"),
  ).json()) as { bytecode?: string };
  if (!circuit.bytecode) throw new Error(`${workload} circuit has no bytecode`);
  const bytecodeDestination = join(
    options.output,
    "fixtures",
    workload,
    "bytecode.gz",
  );
  await Bun.write(bytecodeDestination, Buffer.from(circuit.bytecode, "base64"));

  const publicInputs = (await Bun.file(
    join(fixtureRoot, workload, "public-inputs.json"),
  ).json()) as string[];
  const publicInputBytes = Buffer.concat(
    publicInputs.map((value) => {
      const hex = value.replace(/^0x/, "").padStart(64, "0");
      if (!/^[0-9a-f]{64}$/i.test(hex)) {
        throw new Error(`${workload} has an invalid public input`);
      }
      return Buffer.from(hex, "hex");
    }),
  );
  const publicInputsDestination = join(
    options.output,
    "fixtures",
    workload,
    "public_inputs",
  );
  await Bun.write(publicInputsDestination, publicInputBytes);

  for (const generated of [
    {
      path: bytecodeDestination,
      role: `fixture:${workload}:native-bytecode`,
    },
    {
      path: publicInputsDestination,
      role: `fixture:${workload}:native-public-inputs`,
    },
  ]) {
    const metadata = await stat(generated.path);
    assets.push({
      path: relative(options.output, generated.path),
      role: generated.role,
      bytes: metadata.size,
      sha256: await sha256(generated.path),
    });
  }
}

const manifest = {
  schema_version: 1,
  backend: "barretenberg",
  backend_version: "0.87.0",
  noir_version: "1.0.0-beta.11",
  upstream_commit: "9081b0ed38c43c120afb7c80f8f6cd418ca5ad70",
  platform: options.platform,
  network_at_device: false,
  assets,
};
await writeFile(
  join(options.output, "package-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
);
const runtimeManifest = {
  ...manifest,
  assets: assets.filter(
    (asset) =>
      asset.role !== "native-adapter-library" &&
      asset.role !== "native-upstream-library",
  ),
};
await writeFile(
  join(options.output, "runtime-package-manifest.json"),
  `${JSON.stringify(runtimeManifest, null, 2)}\n`,
);
console.log(join(options.output, "package-manifest.json"));
