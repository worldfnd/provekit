import { constants, copyFile, mkdir } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

const [inputArgument, startArgument, outputArgument] = process.argv.slice(2);
if (!inputArgument || !startArgument || !outputArgument) {
  throw new Error("usage: bun slice-ios-prebuilt.ts INPUT_MANIFEST START_INDEX OUTPUT_ROOT");
}

const inputManifest = resolve(inputArgument);
const inputRoot = dirname(inputManifest);
const outputRoot = resolve(outputArgument);
const startIndex = Number(startArgument);
if (!Number.isInteger(startIndex) || startIndex < 0) throw new Error("START_INDEX must be a non-negative integer");
if (!outputRoot.includes("/target/v1-benchmarks/") || !outputRoot.endsWith("-ios-prebuilt")) {
  throw new Error("OUTPUT_ROOT must be a target/v1-benchmarks/*-ios-prebuilt directory");
}
if (await Bun.file(resolve(outputRoot, "manifest.json")).exists()) {
  throw new Error(`refusing to replace existing sliced manifest at ${outputRoot}`);
}

const manifest = await Bun.file(inputManifest).json();
if (manifest.schema !== "mobench.prebuilt.v1" || manifest.platform !== "ios") {
  throw new Error(`${inputManifest} is not an iOS Mobench prebuilt manifest`);
}
const selected = manifest.entries.slice(startIndex);
if (!selected.length) throw new Error(`slice starting at ${startIndex} is empty`);

for (let index = 0; index < selected.length; index++) {
  const entry = selected[index];
  const destination = resolve(outputRoot, "entries", String(index).padStart(4, "0"));
  await mkdir(destination, { recursive: true });
  for (const artifact of entry.artifacts) {
    const source = resolve(inputRoot, artifact.path);
    const filename = basename(artifact.path);
    await copyFile(source, resolve(destination, filename), constants.COPYFILE_FICLONE);
    artifact.path = `entries/${String(index).padStart(4, "0")}/${filename}`;
  }
}
manifest.entries = selected;
await Bun.write(resolve(outputRoot, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`${outputRoot}/manifest.json: ${selected.length} entries from index ${startIndex}`);
