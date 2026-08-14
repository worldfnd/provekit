#!/usr/bin/env bun

import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  readFile,
  readdir,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { basename, join, resolve } from "node:path";

type Platform = "ios" | "android";
type Asset = {
  path: string;
  role: string;
  bytes: number;
  sha256: string;
};
type Manifest = {
  schema_version: number;
  backend: string;
  backend_version: string;
  noir_version: string;
  upstream_commit: string;
  platform: Platform;
  network_at_device: boolean;
  assets: Asset[];
};

function usage(): never {
  throw new Error(
    "usage: embed-barretenberg-mobile-runtime.ts " +
      "--platform <ios|android> --package-root <directory> --app-root <directory>",
  );
}

function options(args: string[]): {
  platform: Platform;
  packageRoot: string;
  appRoot: string;
} {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag?.startsWith("--") || !value) usage();
    values.set(flag.slice(2), value);
  }
  const platform = values.get("platform");
  const packageRoot = values.get("package-root");
  const appRoot = values.get("app-root");
  if (
    (platform !== "ios" && platform !== "android") ||
    !packageRoot ||
    !appRoot
  ) {
    usage();
  }
  return {
    platform,
    packageRoot: resolve(packageRoot),
    appRoot: resolve(appRoot),
  };
}

function encodedResourceName(path: string): string {
  let encoded = path.replaceAll("/", "_").replaceAll(".", "_").replaceAll("-", "_");
  while (encoded.includes("__")) encoded = encoded.replaceAll("__", "_");
  return `libmobench_bb_v087_${encoded}.so`;
}

async function sha256(path: string): Promise<string> {
  return createHash("sha256")
    .update(new Uint8Array(await Bun.file(path).arrayBuffer()))
    .digest("hex");
}

const selected = options(Bun.argv.slice(2));
const manifestPath = join(
  selected.packageRoot,
  "runtime-package-manifest.json",
);
const manifest = (await Bun.file(manifestPath).json()) as Manifest;
if (
  manifest.schema_version !== 1 ||
  manifest.backend !== "barretenberg" ||
  manifest.backend_version !== "0.87.0" ||
  manifest.noir_version !== "1.0.0-beta.11" ||
  manifest.upstream_commit !==
    "9081b0ed38c43c120afb7c80f8f6cd418ca5ad70" ||
  manifest.platform !== selected.platform ||
  manifest.network_at_device ||
  manifest.assets.some((asset) => asset.role.startsWith("native-"))
) {
  throw new Error("runtime package identity or asset contract mismatch");
}

const destination =
  selected.platform === "android"
    ? join(selected.appRoot, "app/src/main/jniLibs/arm64-v8a")
    : join(selected.appRoot, "BenchRunner/BenchRunner/Resources");
await mkdir(destination, { recursive: true });
if (selected.platform === "ios") {
  const projectPath = join(selected.appRoot, "BenchRunner/project.yml");
  let project = await readFile(projectPath, "utf8");
  if (!project.includes('OTHER_LDFLAGS: "$(inherited) -lz"')) {
    const headerSearch =
      '        HEADER_SEARCH_PATHS: "$(PROJECT_DIR)/BenchRunner/Generated"\n';
    if (!project.includes(headerSearch)) {
      throw new Error("generated iOS project has no expected app link settings");
    }
    project = project.replace(
      headerSearch,
      `${headerSearch}        OTHER_LDFLAGS: "$(inherited) -lz"\n`,
    );
    await writeFile(projectPath, project);
  }
} else {
  const gradlePath = join(selected.appRoot, "app/build.gradle");
  let gradle = await readFile(gradlePath, "utf8");
  const minSdkPattern = /minSdk(?:Version)?\s*[= ]\s*(\d+)/;
  const minSdkMatch = gradle.match(minSdkPattern);
  if (!minSdkMatch) {
    throw new Error("generated Android project has no minSdk declaration");
  }
  const generatedMinSdk = Number(minSdkMatch[1]);
  if (generatedMinSdk > 28) {
    throw new Error(
      `generated Android minSdk ${generatedMinSdk} exceeds the campaign API 28 contract`,
    );
  }
  gradle = gradle.replace(minSdkPattern, "minSdk 28");
  if (!gradle.includes("useLegacyPackaging true")) {
    gradle = gradle.replace(
      "jniLibs {\n",
      "jniLibs {\n            useLegacyPackaging true\n",
    );
  }
  if (!gradle.includes("libmobench_bb_v087_*.so")) {
    gradle = gradle.replace(
      'keepDebugSymbols += ["**/libprovekit_v1_barretenberg_mobile.so"]',
      'keepDebugSymbols += ["**/libprovekit_v1_barretenberg_mobile.so", ' +
        '"**/libmobench_bb_v087_*.so"]',
    );
  }
  await writeFile(gradlePath, gradle);
}
for (const entry of await readdir(destination)) {
  if (entry.startsWith("libmobench_bb_v087_") && entry.endsWith(".so")) {
    await unlink(join(destination, entry));
  }
}

const inputs = [
  {
    path: "runtime-package-manifest.json",
    bytes: (await stat(manifestPath)).size,
    sha256: await sha256(manifestPath),
  },
  ...manifest.assets,
];
const embedded = [];
for (const input of inputs) {
  if (
    input.path.startsWith("/") ||
    input.path.split("/").some((part) => part === "" || part === "..")
  ) {
    throw new Error(`unsafe runtime asset path: ${input.path}`);
  }
  const source = join(selected.packageRoot, input.path);
  const metadata = await stat(source);
  if (
    !metadata.isFile() ||
    metadata.size !== input.bytes ||
    (await sha256(source)) !== input.sha256
  ) {
    throw new Error(`runtime asset integrity mismatch: ${input.path}`);
  }
  const name = encodedResourceName(input.path);
  const output = join(destination, name);
  await copyFile(source, output);
  embedded.push({
    source: input.path,
    embedded: basename(output),
    bytes: input.bytes,
    sha256: input.sha256,
  });
}

console.log(
  JSON.stringify(
    {
      schema_version: 1,
      platform: selected.platform,
      package_manifest_sha256: await sha256(manifestPath),
      destination,
      embedded,
    },
    null,
    2,
  ),
);
