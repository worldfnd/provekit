#!/usr/bin/env bun

import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import {
  isSha256,
  isSourceSha,
  sha256File,
  slugify,
  writeJsonAtomic,
} from "./android-appium-evidence";

type JsonObject = Record<string, unknown>;

interface PrebuiltArtifact {
  kind: string;
  path: string;
  size: number;
  sha256: string;
}

interface PrebuiltEntry {
  function: string;
  iterations: number;
  warmup: number;
  artifacts: PrebuiltArtifact[];
}

interface PrebuiltManifest {
  schema: string;
  source_sha: string;
  platform: string;
  mobench_version: string;
  entries: PrebuiltEntry[];
}

interface Options {
  manifest: string;
  projectDir: string;
  outputDir: string;
  bundletoolJar?: string;
  onlyFunctions: Set<string>;
  dryRun: boolean;
  keystore?: string;
  keyAlias?: string;
  allowUnsigned: boolean;
}

function usage(): never {
  console.error(`usage: bun benchmarks/v1/scripts/prepare-android-release-aabs.ts [options]

Build function-isolated release AABs from a Mobench prebuilt APK manifest and a
matching generated Mobench Android project. The benchmark native library and
bench_spec.json are extracted from each immutable source APK before building.

Required:
  --manifest PATH          Android mobench.prebuilt.v1 manifest
  --project-dir PATH       Generated Mobench Android Gradle project
  --output-dir PATH        Destination for release AABs and manifest.json

Validation/build options:
  --bundletool-jar PATH    Standalone bundletool-all jar for universal APK check
  --only-function NAME     Build one function (repeatable)
  --keystore PATH          AAB signing keystore
  --key-alias ALIAS        AAB signing key alias
  --allow-unsigned         Local diagnostics only; output is runner-ineligible
  --dry-run                Validate inputs without modifying/building the project

Signing passwords are read only from MOBENCH_ANDROID_STORE_PASSWORD and
MOBENCH_ANDROID_KEY_PASSWORD. They are never accepted on the command line.`);
  process.exit(2);
}

function parseArgs(argv: string[]): Options {
  let manifest = "";
  let projectDir = "";
  let outputDir = "";
  let bundletoolJar: string | undefined;
  let keystore: string | undefined;
  let keyAlias: string | undefined;
  let dryRun = false;
  let allowUnsigned = false;
  const onlyFunctions = new Set<string>();
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index]!;
    const next = () => argv[++index] ?? usage();
    switch (value) {
      case "--manifest":
        manifest = next();
        break;
      case "--project-dir":
        projectDir = next();
        break;
      case "--output-dir":
        outputDir = next();
        break;
      case "--bundletool-jar":
        bundletoolJar = next();
        break;
      case "--only-function":
        onlyFunctions.add(next());
        break;
      case "--keystore":
        keystore = next();
        break;
      case "--key-alias":
        keyAlias = next();
        break;
      case "--allow-unsigned":
        allowUnsigned = true;
        break;
      case "--dry-run":
        dryRun = true;
        break;
      case "-h":
      case "--help":
        usage();
      default:
        throw new Error(`unknown argument: ${value}`);
    }
  }
  if (!manifest || !projectDir || !outputDir) usage();
  if ((keystore && !keyAlias) || (!keystore && keyAlias)) {
    throw new Error("--keystore and --key-alias must be provided together");
  }
  if (!dryRun && !allowUnsigned && (!keystore || !keyAlias)) {
    throw new Error(
      "signed output is required; provide --keystore and --key-alias",
    );
  }
  if (
    !dryRun &&
    keystore &&
    (!process.env.MOBENCH_ANDROID_STORE_PASSWORD ||
      !process.env.MOBENCH_ANDROID_KEY_PASSWORD)
  ) {
    throw new Error(
      "set MOBENCH_ANDROID_STORE_PASSWORD and MOBENCH_ANDROID_KEY_PASSWORD locally",
    );
  }
  return {
    manifest: resolve(manifest),
    projectDir: resolve(projectDir),
    outputDir: resolve(outputDir),
    bundletoolJar: bundletoolJar ? resolve(bundletoolJar) : undefined,
    onlyFunctions,
    dryRun,
    keystore: keystore ? resolve(keystore) : undefined,
    keyAlias,
    allowUnsigned,
  };
}

async function command(
  args: string[],
  options: { cwd?: string; stdoutPath?: string; env?: Record<string, string> } = {},
): Promise<string> {
  const processHandle = Bun.spawn(args, {
    cwd: options.cwd,
    env: { ...process.env, ...options.env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(processHandle.stdout).text(),
    new Response(processHandle.stderr).text(),
    processHandle.exited,
  ]);
  if (options.stdoutPath) {
    await Bun.write(
      options.stdoutPath,
      `${stdout}${stderr ? `\n${stderr}` : ""}`,
    );
  }
  if (exitCode !== 0) {
    throw new Error(
      `${basename(args[0]!)} failed with exit ${exitCode}: ${stderr.trim().slice(-2000)}`,
    );
  }
  return stdout;
}

async function archiveEntries(path: string): Promise<string[]> {
  return (await command(["unzip", "-Z1", path]))
    .split(/\r?\n/)
    .filter(Boolean);
}

async function archiveBytes(path: string, entry: string): Promise<Uint8Array> {
  const child = Bun.spawn(["unzip", "-p", path, entry], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const [bytes, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).bytes(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(`could not extract ${entry} from ${path}: ${stderr.trim()}`);
  }
  return bytes;
}

function asObject(value: unknown, name: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as JsonObject;
}

async function loadPrebuilt(path: string): Promise<PrebuiltManifest> {
  const value = asObject(await Bun.file(path).json(), "prebuilt manifest");
  if (
    value.schema !== "mobench.prebuilt.v1" ||
    value.platform !== "android" ||
    !isSourceSha(value.source_sha) ||
    typeof value.mobench_version !== "string" ||
    !Array.isArray(value.entries) ||
    value.entries.length === 0
  ) {
    throw new Error("invalid Android mobench.prebuilt.v1 manifest");
  }
  const seen = new Set<string>();
  for (const [index, raw] of value.entries.entries()) {
    const entry = asObject(raw, `entry ${index}`);
    if (
      typeof entry.function !== "string" ||
      seen.has(entry.function) ||
      entry.iterations !== 5 ||
      entry.warmup !== 1 ||
      !Array.isArray(entry.artifacts)
    ) {
      throw new Error(
        `entry ${index} must have a unique function and warmup=1 iterations=5`,
      );
    }
    seen.add(entry.function);
  }
  return value as unknown as PrebuiltManifest;
}

async function verifySourceApk(
  manifestDir: string,
  entry: PrebuiltEntry,
): Promise<{
  apkPath: string;
  apkSha256: string;
  nativePath: string;
  nativeBytes: Uint8Array;
  nativeSha256: string;
  specBytes: Uint8Array;
  specSha256: string;
}> {
  const artifact = entry.artifacts.find(
    (candidate) => candidate.kind === "android-app",
  );
  if (
    !artifact ||
    !isSha256(artifact.sha256) ||
    !Number.isSafeInteger(artifact.size)
  ) {
    throw new Error(`${entry.function} has no valid android-app artifact`);
  }
  const apkPath = resolve(manifestDir, artifact.path);
  const apkHash = await sha256File(apkPath);
  if (
    apkHash !== artifact.sha256 ||
    Bun.file(apkPath).size !== artifact.size
  ) {
    throw new Error(`${entry.function} source APK failed immutable validation`);
  }
  const entries = await archiveEntries(apkPath);
  const benchmarkLibraries = entries.filter(
    (path) =>
      /^lib\/arm64-v8a\/lib[^/]+\.so$/.test(path) &&
      !path.endsWith("/libjnidispatch.so") &&
      !path.includes("/libmobench_bb_v087_"),
  );
  if (benchmarkLibraries.length !== 1) {
    throw new Error(
      `${entry.function} source APK must contain exactly one arm64 benchmark library; found ${benchmarkLibraries.join(",")}`,
    );
  }
  const nativePath = benchmarkLibraries[0]!;
  const nativeBytes = await archiveBytes(apkPath, nativePath);
  const specBytes = await archiveBytes(apkPath, "assets/bench_spec.json");
  const spec = JSON.parse(new TextDecoder().decode(specBytes)) as JsonObject;
  if (
    spec.function !== entry.function ||
    spec.iterations !== 5 ||
    spec.warmup !== 1
  ) {
    throw new Error(`${entry.function} source APK bench_spec contract mismatch`);
  }
  return {
    apkPath,
    apkSha256: apkHash,
    nativePath,
    nativeBytes,
    nativeSha256: new Bun.CryptoHasher("sha256")
      .update(nativeBytes)
      .digest("hex"),
    specBytes,
    specSha256: new Bun.CryptoHasher("sha256")
      .update(specBytes)
      .digest("hex"),
  };
}

async function signingFingerprint(aabPath: string): Promise<string | null> {
  const javaTool = (name: string) =>
    process.env.JAVA_HOME ? join(process.env.JAVA_HOME, "bin", name) : name;
  const check = Bun.spawnSync([javaTool("jarsigner"), "-verify", aabPath], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const verification = `${check.stdout.toString()}\n${check.stderr.toString()}`;
  if (check.exitCode !== 0 || !verification.includes("jar verified.")) {
    return null;
  }
  const output = await command([
    javaTool("keytool"),
    "-printcert",
    "-jarfile",
    aabPath,
  ]);
  const match = output.match(/SHA256:\s*([0-9A-F:]{95})/);
  if (!match) throw new Error(`could not resolve signing fingerprint: ${aabPath}`);
  return match[1]!.replaceAll(":", "").toLowerCase();
}

async function validateAabPayload(
  aabPath: string,
  nativeFilename: string,
  expectedNativeSha: string,
  expectedSpecSha: string,
): Promise<{ nativePath: string; specPath: string }> {
  const entries = await archiveEntries(aabPath);
  const nativePath = `base/lib/arm64-v8a/${nativeFilename}`;
  const specPath = "base/assets/bench_spec.json";
  if (!entries.includes(nativePath) || !entries.includes(specPath)) {
    throw new Error(`${basename(aabPath)} is missing its native library or spec`);
  }
  const nativeHash = new Bun.CryptoHasher("sha256")
    .update(await archiveBytes(aabPath, nativePath))
    .digest("hex");
  const specHash = new Bun.CryptoHasher("sha256")
    .update(await archiveBytes(aabPath, specPath))
    .digest("hex");
  if (nativeHash !== expectedNativeSha || specHash !== expectedSpecSha) {
    throw new Error(`${basename(aabPath)} embedded payload differs from source APK`);
  }
  return { nativePath, specPath };
}

async function validateUniversalApk(
  bundletoolJar: string,
  aabPath: string,
  temporaryDir: string,
  nativeFilename: string,
  expectedNativeSha: string,
  expectedSpecSha: string,
): Promise<{ sha256: string; bytes: number }> {
  const archive = join(temporaryDir, "universal.apks");
  await command([
    process.env.JAVA_HOME
      ? join(process.env.JAVA_HOME, "bin", "java")
      : "java",
    "-jar",
    bundletoolJar,
    "build-apks",
    `--bundle=${aabPath}`,
    `--output=${archive}`,
    "--mode=universal",
    "--overwrite",
  ]);
  const universal = join(temporaryDir, "universal.apk");
  await Bun.write(universal, await archiveBytes(archive, "universal.apk"));
  const entries = await archiveEntries(universal);
  const nativePath = `lib/arm64-v8a/${nativeFilename}`;
  if (
    !entries.includes(nativePath) ||
    !entries.includes("assets/bench_spec.json")
  ) {
    throw new Error("bundletool universal APK is missing the benchmark payload");
  }
  const nativeHash = new Bun.CryptoHasher("sha256")
    .update(await archiveBytes(universal, nativePath))
    .digest("hex");
  const specHash = new Bun.CryptoHasher("sha256")
    .update(await archiveBytes(universal, "assets/bench_spec.json"))
    .digest("hex");
  if (nativeHash !== expectedNativeSha || specHash !== expectedSpecSha) {
    throw new Error("bundletool universal APK differs from the source APK");
  }
  return {
    sha256: await sha256File(universal),
    bytes: Bun.file(universal).size,
  };
}

async function main(): Promise<void> {
  const options = parseArgs(Bun.argv.slice(2));
  const manifest = await loadPrebuilt(options.manifest);
  const manifestDir = dirname(options.manifest);
  let buildProjectDir = options.projectDir;
  let gradlew = join(buildProjectDir, "gradlew");
  const mainActivityRoot = join(
    options.projectDir,
    "app",
    "src",
    "main",
    "java",
  );
  if (
    !(await Bun.file(gradlew).exists()) ||
    !(await Bun.file(join(options.projectDir, "app", "build.gradle")).exists())
  ) {
    throw new Error("--project-dir is not a generated Mobench Android project");
  }
  const sourceFiles = (
    await command(["find", mainActivityRoot, "-type", "f", "-name", "*.kt"])
  )
    .split(/\r?\n/)
    .filter(Boolean);
  if (sourceFiles.length === 0) {
    throw new Error("generated Mobench Android project has no Kotlin runner");
  }
  const runnerSource = (
    await Promise.all(sourceFiles.map((path) => Bun.file(path).text()))
  ).join("\n");
  if (
    !runnerSource.includes("BENCH_JSON_CHUNK") ||
    !runnerSource.includes("BENCH_JSON_START") ||
    !runnerSource.includes("BENCH_JSON_END")
  ) {
    throw new Error("Mobench Android runner lacks chunked BENCH_JSON evidence");
  }

  const selected = manifest.entries.filter(
    (entry) =>
      options.onlyFunctions.size === 0 ||
      options.onlyFunctions.has(entry.function),
  );
  if (selected.length === 0) throw new Error("no selected function was found");
  for (const requested of options.onlyFunctions) {
    if (!selected.some((entry) => entry.function === requested)) {
      throw new Error(`unknown --only-function: ${requested}`);
    }
  }

  if (options.dryRun) {
    let verifiedSources = 0;
    const nativeNames = new Set<string>();
    for (const entry of selected) {
      const source = await verifySourceApk(manifestDir, entry);
      nativeNames.add(basename(source.nativePath));
      verifiedSources += 1;
    }
    if (nativeNames.size !== 1) {
      throw new Error("selected APKs do not share one benchmark library name");
    }
    console.log(
      JSON.stringify(
        {
          schema: "provekit.android-release-aab-dry-run.v1",
          source_sha: manifest.source_sha,
          mobench_version: manifest.mobench_version,
          project_dir: options.projectDir,
          selected_functions: selected.map((entry) => entry.function),
          source_apks_verified: verifiedSources,
          contract: { warmup: 1, iterations: 5 },
          signed_build_requested: !options.allowUnsigned,
          bundletool_validation_requested: Boolean(options.bundletoolJar),
        },
        null,
        2,
      ),
    );
    return;
  }

  await mkdir(options.outputDir, { recursive: true });
  const isolatedProjectDir = await mkdtemp(
    join(options.outputDir, ".android-project-"),
  );
  await command([
    "rsync",
    "-a",
    "--exclude=.gradle",
    "--exclude=app/build",
    `${options.projectDir}/`,
    `${isolatedProjectDir}/`,
  ]);
  buildProjectDir = isolatedProjectDir;
  gradlew = join(buildProjectDir, "gradlew");
  const cleanupIsolatedProject = () => {
    Bun.spawnSync(["rm", "-rf", "--", isolatedProjectDir], {
      stdout: "ignore",
      stderr: "ignore",
    });
  };
  process.once("exit", cleanupIsolatedProject);
  const buildLogDir = join(options.outputDir, "build-logs");
  await mkdir(buildLogDir, { recursive: true });
  const projectNativeDir = join(
    buildProjectDir,
    "app",
    "src",
    "main",
    "jniLibs",
    "arm64-v8a",
  );
  const projectSpec = join(
    buildProjectDir,
    "app",
    "src",
    "main",
    "assets",
    "bench_spec.json",
  );
  await mkdir(projectNativeDir, { recursive: true });
  await mkdir(dirname(projectSpec), { recursive: true });
  const outputs: JsonObject[] = [];

  for (let index = 0; index < selected.length; index += 1) {
    const entry = selected[index]!;
    // Load one immutable APK payload at a time. Passport APKs are large enough
    // that retaining all fourteen native libraries can exhaust a CI runner.
    const source = await verifySourceApk(manifestDir, entry);
    const functionSlug = slugify(entry.function);
    const nativeFilename = basename(source.nativePath);
    await Bun.write(join(projectNativeDir, nativeFilename), source.nativeBytes);
    await Bun.write(projectSpec, source.specBytes);

    const logPath = join(buildLogDir, `${functionSlug}.log`);
    await command([gradlew, "clean", "bundleRelease", "--no-daemon"], {
      cwd: buildProjectDir,
      stdoutPath: logPath,
    });
    const builtAab = join(
      buildProjectDir,
      "app",
      "build",
      "outputs",
      "bundle",
      "release",
      "app-release.aab",
    );
    if (!(await Bun.file(builtAab).exists())) {
      throw new Error(`Gradle did not produce ${builtAab}`);
    }
    const destinationDir = join(
      options.outputDir,
      `${String(index).padStart(4, "0")}-${functionSlug}`,
    );
    await mkdir(destinationDir, { recursive: true });
    const aabPath = join(destinationDir, "app-release.aab");
    await Bun.write(aabPath, Bun.file(builtAab));

    let signed = await signingFingerprint(aabPath);
    if (!signed && options.keystore && options.keyAlias) {
      const jarsigner = process.env.JAVA_HOME
        ? join(process.env.JAVA_HOME, "bin", "jarsigner")
        : "jarsigner";
      await command([
        jarsigner,
        "-keystore",
        options.keystore,
        "-storepass:env",
        "MOBENCH_ANDROID_STORE_PASSWORD",
        "-keypass:env",
        "MOBENCH_ANDROID_KEY_PASSWORD",
        aabPath,
        options.keyAlias,
      ]);
      signed = await signingFingerprint(aabPath);
    }
    if (!signed && !options.allowUnsigned) {
      throw new Error(`${entry.function} release AAB is unsigned`);
    }
    const embedded = await validateAabPayload(
      aabPath,
      nativeFilename,
      source.nativeSha256,
      source.specSha256,
    );
    let universal: JsonObject | null = null;
    if (options.bundletoolJar) {
      const temporaryDir = await mkdtemp(
        join(options.outputDir, `.bundletool-${functionSlug}-`),
      );
      try {
        universal = await validateUniversalApk(
          options.bundletoolJar,
          aabPath,
          temporaryDir,
          nativeFilename,
          source.nativeSha256,
          source.specSha256,
        );
      } finally {
        await rm(temporaryDir, { recursive: true, force: true });
      }
    }
    outputs.push({
      function: entry.function,
      source_apk: {
        path: relative(options.outputDir, source.apkPath),
        sha256: source.apkSha256,
      },
      release_aab: {
        path: relative(options.outputDir, aabPath),
        sha256: await sha256File(aabPath),
        bytes: Bun.file(aabPath).size,
      },
      embedded_native_library: {
        archive_path: embedded.nativePath,
        sha256: source.nativeSha256,
      },
      embedded_bench_spec: {
        archive_path: embedded.specPath,
        sha256: source.specSha256,
      },
      universal_apk_validation: universal,
      build_profile: "release",
      signed: Boolean(signed),
      signing_certificate_sha256: signed,
      source_payload_matches: true,
      build_log: relative(options.outputDir, logPath),
    });
    console.log(`[built] ${entry.function}: ${aabPath}`);
  }

  await writeJsonAtomic(join(options.outputDir, "manifest.json"), {
    schema: "provekit.android-release-aabs.v1",
    generated_at: new Date().toISOString(),
    source_sha: manifest.source_sha,
    source_manifest: options.manifest,
    source_manifest_sha256: await sha256File(options.manifest),
    mobench_version: manifest.mobench_version,
    project_dir: options.projectDir,
    wrapper_source_sha256: new Bun.CryptoHasher("sha256")
      .update(runnerSource)
      .digest("hex"),
    warmup: 1,
    iterations: 5,
    entries: outputs,
  });
  process.off("exit", cleanupIsolatedProject);
  await rm(isolatedProjectDir, { recursive: true, force: true });
  console.log(`Wrote ${join(options.outputDir, "manifest.json")}`);
}

await main();
