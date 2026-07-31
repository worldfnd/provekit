#!/usr/bin/env bun

import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

type Artifact = {
  kind: string;
  path: string;
  size: number;
  sha256: string;
};

type Entry = {
  function: string;
  iterations: number;
  warmup: number;
  completion_timeout_secs: number;
  artifacts: Artifact[];
};

type Manifest = {
  schema: string;
  source_sha: string;
  platform: string;
  build_profile: string;
  mobench_version: string;
  abi: unknown;
  entries: Entry[];
};

const [sourceArg, outputArg, indicesArg] = process.argv.slice(2);
if (!sourceArg || !outputArg || !indicesArg) {
  throw new Error(
    "usage: bun slice-ios-prebuilt-manifest.ts <source-manifest> <output-root> <comma-separated-indices>",
  );
}

const sourceManifest = resolve(sourceArg);
const sourceRoot = dirname(sourceManifest);
const outputRoot = resolve(outputArg);
const indices = indicesArg.split(",").map((value) => {
  const index = Number(value);
  if (!Number.isInteger(index) || index < 0) {
    throw new Error(`invalid manifest index: ${value}`);
  }
  return index;
});
if (new Set(indices).size !== indices.length) {
  throw new Error("manifest indices must be unique");
}

const manifest = JSON.parse(
  await readFile(sourceManifest, "utf8"),
) as Manifest;
if (manifest.schema !== "mobench.prebuilt.v1" || manifest.platform !== "ios") {
  throw new Error("source must be a mobench.prebuilt.v1 iOS manifest");
}

const selections = indices.map((index) => {
  const entry = manifest.entries[index];
  if (!entry) throw new Error(`manifest has no entry at index ${index}`);
  return { entry, sourceIndex: index };
});

await mkdir(outputRoot, { recursive: true });
const entries = [];
for (const [outputIndex, selection] of selections.entries()) {
  const artifacts = [];
  for (const artifact of selection.entry.artifacts) {
    if (isAbsolute(artifact.path) || artifact.path.split("/").includes("..")) {
      throw new Error(`unsafe artifact path: ${artifact.path}`);
    }
    const source = join(sourceRoot, artifact.path);
    const outputPath = join(
      "entries",
      String(outputIndex).padStart(4, "0"),
      basename(artifact.path),
    );
    const destination = join(outputRoot, outputPath);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(source, destination);
    artifacts.push({ ...artifact, path: outputPath });
  }
  entries.push({ ...selection.entry, artifacts });
}

await writeFile(
  join(outputRoot, "manifest.json"),
  `${JSON.stringify({ ...manifest, entries }, null, 2)}\n`,
);
console.log(join(outputRoot, "manifest.json"));
