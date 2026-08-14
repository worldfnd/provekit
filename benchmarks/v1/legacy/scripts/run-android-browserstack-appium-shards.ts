#!/usr/bin/env bun

import { mkdir } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import {
  type AabEntry,
  type BenchResult,
  loadAndVerifyAabManifest,
  parseDevice,
  reconstructBenchResults,
  sha256File,
  slugify,
  verifyBenchContract,
  writeJsonAtomic,
} from "./android-appium-evidence";

type JsonObject = Record<string, unknown>;

interface Options {
  manifest: string;
  outputDir: string;
  devices: ReturnType<typeof parseDevice>[];
  onlyFunctions: Set<string>;
  dryRun: boolean;
  confirmPaid: boolean;
  retryFailed: boolean;
  timeoutSeconds: number;
}

interface WebDriverResponse<T> {
  sessionId?: string;
  value?: T & { error?: string; message?: string };
}

const uploadEndpoint = "https://api-cloud.browserstack.com/app-automate/upload";
const apiRoot = "https://api-cloud.browserstack.com/app-automate";
const hubRoot = "https://hub-cloud.browserstack.com/wd/hub";

function usage(): never {
  console.error(`usage: bun benchmarks/v1/scripts/run-android-browserstack-appium-shards.ts [options]

Run one generic App Automate AAB in one Appium session per function/device.
Completed shards resume safely and all retained evidence is credential-free.

Required:
  --manifest PATH                    prepare-android-release-aabs manifest
  --output-dir PATH                  persistent evidence directory

Selection/control:
  --device "Device Name-OS.Version"  repeatable (default: Google Pixel 7-13.0)
  --only-function NAME               repeatable
  --timeout-secs N                   per-session cap (default: 7200)
  --retry-failed                     retry failed shards
  --dry-run                          validate all selected AABs, no network
  --confirm-paid-browserstack        required for uploads/device sessions

Credentials are read only from BROWSERSTACK_USERNAME and
BROWSERSTACK_ACCESS_KEY. They are never written to evidence.`);
  process.exit(2);
}

function parseArgs(argv: string[]): Options {
  let manifest = "";
  let outputDir = "";
  const devices: ReturnType<typeof parseDevice>[] = [];
  const onlyFunctions = new Set<string>();
  let dryRun = false;
  let confirmPaid = false;
  let retryFailed = false;
  let timeoutSeconds = 7200;
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index]!;
    const next = () => argv[++index] ?? usage();
    switch (value) {
      case "--manifest":
        manifest = next();
        break;
      case "--output-dir":
        outputDir = next();
        break;
      case "--device":
        devices.push(parseDevice(next()));
        break;
      case "--only-function":
        onlyFunctions.add(next());
        break;
      case "--timeout-secs":
        timeoutSeconds = Number.parseInt(next(), 10);
        break;
      case "--retry-failed":
        retryFailed = true;
        break;
      case "--dry-run":
        dryRun = true;
        break;
      case "--confirm-paid-browserstack":
        confirmPaid = true;
        break;
      case "-h":
      case "--help":
        usage();
      default:
        throw new Error(`unknown argument: ${value}`);
    }
  }
  if (!manifest || !outputDir) usage();
  if (
    !Number.isSafeInteger(timeoutSeconds) ||
    timeoutSeconds < 60 ||
    timeoutSeconds > 14400
  ) {
    throw new Error("--timeout-secs must be an integer from 60 to 14400");
  }
  if (dryRun && confirmPaid) {
    throw new Error("--dry-run and --confirm-paid-browserstack conflict");
  }
  if (!dryRun && !confirmPaid) {
    throw new Error(
      "refusing paid calls without --confirm-paid-browserstack; use --dry-run first",
    );
  }
  return {
    manifest: resolve(manifest),
    outputDir: resolve(outputDir),
    devices:
      devices.length > 0 ? devices : [parseDevice("Google Pixel 7-13.0")],
    onlyFunctions,
    dryRun,
    confirmPaid,
    retryFailed,
    timeoutSeconds,
  };
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`set ${name} locally`);
  return value;
}

function basicAuthorization(username: string, accessKey: string): string {
  return `Basic ${Buffer.from(`${username}:${accessKey}`).toString("base64")}`;
}

async function parseResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function request(
  url: string,
  authorization: string,
  init: RequestInit = {},
): Promise<unknown> {
  const response = await fetch(url, {
    ...init,
    headers: { Authorization: authorization, ...init.headers },
  });
  const payload = await parseResponse(response);
  if (!response.ok) {
    const object =
      payload && typeof payload === "object" ? (payload as JsonObject) : {};
    const message =
      typeof object.message === "string"
        ? object.message
        : typeof object.error === "string"
          ? object.error
          : response.statusText;
    throw new Error(`${response.status} ${message}`);
  }
  return payload;
}

async function webdriver<T>(
  path: string,
  authorization: string,
  method: "GET" | "POST" | "DELETE",
  body?: unknown,
): Promise<WebDriverResponse<T>> {
  const payload = (await request(`${hubRoot}${path}`, authorization, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  })) as WebDriverResponse<T>;
  if (payload.value?.error) {
    throw new Error(
      `WebDriver ${method} ${path} failed: ${payload.value.message ?? payload.value.error}`,
    );
  }
  return payload;
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

async function verifyEmbeddedPayload(entry: AabEntry): Promise<void> {
  const nativeHash = new Bun.CryptoHasher("sha256")
    .update(
      await archiveBytes(
        entry.release_aab.path,
        entry.embedded_native_library.archive_path,
      ),
    )
    .digest("hex");
  const specBytes = await archiveBytes(
    entry.release_aab.path,
    entry.embedded_bench_spec.archive_path,
  );
  const specHash = new Bun.CryptoHasher("sha256")
    .update(specBytes)
    .digest("hex");
  if (
    nativeHash !== entry.embedded_native_library.sha256 ||
    specHash !== entry.embedded_bench_spec.sha256
  ) {
    throw new Error(`${entry.function} embedded payload hash mismatch`);
  }
  const spec = JSON.parse(new TextDecoder().decode(specBytes)) as JsonObject;
  if (
    spec.function !== entry.function ||
    spec.warmup !== 1 ||
    spec.iterations !== 5
  ) {
    throw new Error(`${entry.function} embedded bench_spec contract mismatch`);
  }
}

async function uploadAab(
  entry: AabEntry,
  sourceSha: string,
  authorization: string,
  shardDir: string,
): Promise<{ appHandle: string; customId: string }> {
  const started = performance.now();
  const customId =
    `pkv1-${slugify(entry.function).slice(-48)}-` +
    new Date().toISOString().replaceAll(/[-:.]/g, "").toLowerCase();
  const form = new FormData();
  form.set("file", Bun.file(entry.release_aab.path), basename(entry.release_aab.path));
  form.set("custom_id", customId);
  const payload = (await request(uploadEndpoint, authorization, {
    method: "POST",
    body: form,
  })) as JsonObject;
  const appHandle =
    typeof payload.app_url === "string"
      ? payload.app_url
      : typeof payload.app_handle === "string"
        ? payload.app_handle
        : undefined;
  if (!appHandle?.startsWith("bs://")) {
    throw new Error("BrowserStack upload returned no app handle");
  }
  await writeJsonAtomic(join(shardDir, "upload.json"), {
    schema: "provekit.browserstack-appium-aab-upload.v1",
    uploaded_at: new Date().toISOString(),
    endpoint: uploadEndpoint,
    custom_id: customId,
    source_sha: sourceSha,
    function: entry.function,
    artifact: {
      filename: basename(entry.release_aab.path),
      bytes: entry.release_aab.bytes,
      sha256: entry.release_aab.sha256,
      embedded_native_library_sha256:
        entry.embedded_native_library.sha256,
      embedded_bench_spec_sha256: entry.embedded_bench_spec.sha256,
      build_profile: "release",
      signed: entry.signed,
    },
    upload: {
      elapsed_seconds: (performance.now() - started) / 1000,
      app_handle: appHandle,
    },
  });
  return { appHandle, customId };
}

async function fetchDeviceLog(
  rawSession: unknown,
  authorization: string,
): Promise<string> {
  const session = sessionObject(rawSession);
  const rawUrl = session.device_logs_url;
  if (typeof rawUrl !== "string") {
    throw new Error("BrowserStack session returned no device log URL");
  }
  const deviceLogUrl = new URL(rawUrl);
  if (deviceLogUrl.protocol !== "https:") {
    throw new Error("BrowserStack session returned a non-HTTPS device log URL");
  }
  let lastError: unknown;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      let response = await fetch(deviceLogUrl);
      if (
        (response.status === 401 || response.status === 403) &&
        deviceLogUrl.hostname.endsWith("browserstack.com")
      ) {
        response = await fetch(deviceLogUrl, {
          headers: { Authorization: authorization },
        });
      }
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const payload = await response.text();
      if (payload.includes("BenchRunner")) {
        return payload;
      }
      lastError = new Error("device log did not yet contain BenchRunner output");
    } catch (error) {
      lastError = error;
    }
    await Bun.sleep(3000);
  }
  throw new Error(
    `device log was unavailable after session completion: ${
      lastError instanceof Error ? lastError.message : String(lastError ?? "")
    }`,
  );
}

function sessionObject(payload: unknown): JsonObject {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return {};
  const object = payload as JsonObject;
  if (
    object.automation_session &&
    typeof object.automation_session === "object" &&
    !Array.isArray(object.automation_session)
  ) {
    return object.automation_session as JsonObject;
  }
  return object;
}

function allowlistedSessionSummary(payload: unknown): JsonObject {
  const session = sessionObject(payload);
  const allowed = [
    "name",
    "duration",
    "os",
    "os_version",
    "device",
    "status",
    "reason",
    "hashed_id",
    "build_name",
    "project_name",
    "build_hashed_id",
    "browserstack_status",
    "created_at",
  ] as const;
  const sanitized: JsonObject = {};
  for (const field of allowed) {
    const value = session[field];
    if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean" ||
      value === null
    ) {
      sanitized[field] = value;
    }
  }
  if (
    session.app_details &&
    typeof session.app_details === "object" &&
    !Array.isArray(session.app_details)
  ) {
    const app = session.app_details as JsonObject;
    const allowedApp = [
      "app_name",
      "app_version",
      "app_custom_id",
      "uploaded_at",
      "app_filename",
    ] as const;
    const sanitizedApp: JsonObject = {};
    for (const field of allowedApp) {
      const value = app[field];
      if (
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean" ||
        value === null
      ) {
        sanitizedApp[field] = value;
      }
    }
    sanitized.app_details = sanitizedApp;
  }
  return sanitized;
}

async function runSession(
  entry: AabEntry,
  sourceSha: string,
  device: ReturnType<typeof parseDevice>,
  options: Options,
  authorization: string,
  username: string,
  accessKey: string,
  shardDir: string,
): Promise<{
  sessionId: string;
  buildId: string | null;
  result: BenchResult;
}> {
  const { appHandle, customId } = await uploadAab(
    entry,
    sourceSha,
    authorization,
    shardDir,
  );
  const buildName = `provekit-v1-aab-${sourceSha.slice(0, 12)}`;
  const sessionName = `${entry.function} ${device.label}`;
  let sessionId: string | undefined;
  let completionObserved = false;
  let lastSourceBytes = 0;
  let deleted = false;
  try {
    const created = await webdriver<{
      sessionId?: string;
      capabilities?: JsonObject;
    }>("/session", authorization, "POST", {
      capabilities: {
        alwaysMatch: {
          platformName: "Android",
          "appium:automationName": "UiAutomator2",
          "appium:app": appHandle,
          "bstack:options": {
            userName: username,
            accessKey,
            deviceName: device.deviceName,
            osVersion: device.osVersion,
            projectName: "ProveKit V1 native Android benchmarks",
            buildName,
            sessionName,
            deviceLogs: true,
            appiumLogs: true,
          },
        },
      },
    });
    sessionId = created.value?.sessionId ?? created.sessionId;
    if (!sessionId) throw new Error("BrowserStack returned no Appium session ID");
    await writeJsonAtomic(join(shardDir, "session.json"), {
      schema: "provekit.browserstack-appium-session-created.v1",
      created_at: new Date().toISOString(),
      app_handle: appHandle,
      app_custom_id: customId,
      session_id: sessionId,
      source_sha: sourceSha,
      function: entry.function,
      requested_device: device,
      project_name: "ProveKit V1 native Android benchmarks",
      build_name: buildName,
      session_name: sessionName,
      credential_source: "env",
    });

    const deadline = Date.now() + options.timeoutSeconds * 1000;
    while (Date.now() < deadline) {
      const source = await webdriver<string>(
        `/session/${sessionId}/source`,
        authorization,
        "GET",
      );
      const text = typeof source.value === "string" ? source.value : "";
      lastSourceBytes = text.length;
      if (
        text.includes(entry.function) &&
        (text.includes("Iterations: 5") ||
          text.includes("Benchmark worker completed") ||
          text.includes("Benchmark Results"))
      ) {
        completionObserved = true;
        break;
      }
      await Bun.sleep(2000);
    }
    if (!completionObserved) {
      throw new Error(
        `${entry.function} timed out after ${options.timeoutSeconds}s`,
      );
    }
    await webdriver(`/session/${sessionId}`, authorization, "DELETE");
    deleted = true;
  } finally {
    if (sessionId && !deleted) {
      await webdriver(`/session/${sessionId}`, authorization, "DELETE").catch(
        () => undefined,
      );
    }
  }
  if (!sessionId) throw new Error("Appium session was not created");

  const rawSummary = await request(
    `${apiRoot}/sessions/${sessionId}.json`,
    authorization,
  );
  const summary = allowlistedSessionSummary(rawSummary);
  await writeJsonAtomic(join(shardDir, "session-summary.json"), {
    schema: "provekit.browserstack-appium-session.v1",
    session: summary,
  });
  const buildId =
    typeof summary.build_hashed_id === "string"
      ? summary.build_hashed_id
      : null;
  await writeJsonAtomic(join(shardDir, "build.json"), {
    schema: "provekit.browserstack-appium-build.v1",
    build_id: buildId,
    build_name:
      typeof summary.build_name === "string" ? summary.build_name : buildName,
    session_id: sessionId,
    source_sha: sourceSha,
  });

  const deviceLog = await fetchDeviceLog(rawSummary, authorization);
  await Bun.write(join(shardDir, "device.log"), deviceLog);
  const candidates = reconstructBenchResults(deviceLog).filter(
    (candidate) => candidate.function === entry.function,
  );
  if (candidates.length !== 1) {
    throw new Error(
      `expected exactly one BENCH_JSON result for ${entry.function}; found ${candidates.length}`,
    );
  }
  const result = candidates[0]!;
  verifyBenchContract(result, entry.function);
  await writeJsonAtomic(join(shardDir, "bench-report.json"), result);
  await writeJsonAtomic(join(shardDir, "result.json"), {
    schema: "provekit.browserstack-appium-result.v1",
    completed_at: new Date().toISOString(),
    source_sha: sourceSha,
    function: entry.function,
    requested_device: device,
    app_handle: appHandle,
    session_id: sessionId,
    build_id: buildId,
    completion_observed: completionObserved,
    last_source_bytes: lastSourceBytes,
    warmup: result.spec.warmup,
    measured_samples: result.samples.length,
    samples_ns: result.samples_ns,
    artifact_sha256: entry.release_aab.sha256,
    artifact_build_profile: entry.build_profile,
  });
  return { sessionId, buildId, result };
}

async function writeIndex(
  outputDir: string,
  sourceSha: string,
  manifestPath: string,
): Promise<void> {
  const find = Bun.spawn(
    ["find", join(outputDir, "shards"), "-type", "f", "-name", "status.json"],
    { stdout: "pipe", stderr: "pipe" },
  );
  const [stdout, exitCode] = await Promise.all([
    new Response(find.stdout).text(),
    find.exited,
  ]);
  const statuses: unknown[] = [];
  if (exitCode === 0) {
    for (const path of stdout.split(/\r?\n/).filter(Boolean).sort()) {
      statuses.push(await Bun.file(path).json());
    }
  }
  statuses.sort((left, right) => {
    const a = left as { function?: string; device?: string };
    const b = right as { function?: string; device?: string };
    return `${a.function ?? ""}\0${a.device ?? ""}`.localeCompare(
      `${b.function ?? ""}\0${b.device ?? ""}`,
    );
  });
  await writeJsonAtomic(join(outputDir, "index.json"), {
    schema: "provekit.android-browserstack-appium-shards.v1",
    updated_at: new Date().toISOString(),
    source_sha: sourceSha,
    source_manifest: manifestPath,
    shards: statuses,
  });
}

async function main(): Promise<void> {
  const options = parseArgs(Bun.argv.slice(2));
  const manifest = await loadAndVerifyAabManifest(options.manifest);
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
  for (const entry of selected) await verifyEmbeddedPayload(entry);

  if (options.dryRun) {
    console.log(
      JSON.stringify(
        {
          schema: "provekit.android-browserstack-appium-dry-run.v1",
          source_sha: manifest.source_sha,
          source_manifest_sha256: await sha256File(options.manifest),
          selected_functions: selected.map((entry) => entry.function),
          devices: options.devices.map((device) => device.label),
          contract: { warmup: 1, iterations: 5 },
          release_aabs_verified: selected.length,
          paid_calls: 0,
        },
        null,
        2,
      ),
    );
    return;
  }

  const username = requiredEnvironment("BROWSERSTACK_USERNAME");
  const accessKey = requiredEnvironment("BROWSERSTACK_ACCESS_KEY");
  const authorization = basicAuthorization(username, accessKey);
  await mkdir(join(options.outputDir, "shards"), { recursive: true });

  for (const entry of selected) {
    for (const device of options.devices) {
      const shardDir = join(
        options.outputDir,
        "shards",
        slugify(entry.function),
        slugify(device.label),
      );
      await mkdir(shardDir, { recursive: true });
      const statusPath = join(shardDir, "status.json");
      if (await Bun.file(statusPath).exists()) {
        const status = (await Bun.file(statusPath).json()) as JsonObject;
        if (status.outcome === "success") {
          const resultPath = join(shardDir, "bench-report.json");
          const identityPath = join(shardDir, "result.json");
          if (
            status.source_sha === manifest.source_sha &&
            status.artifact_sha256 === entry.release_aab.sha256 &&
            (await Bun.file(resultPath).exists()) &&
            (await Bun.file(identityPath).exists())
          ) {
            const retained = (await Bun.file(resultPath).json()) as BenchResult;
            const identity = (await Bun.file(identityPath).json()) as JsonObject;
            if (
              identity.source_sha !== manifest.source_sha ||
              identity.artifact_sha256 !== entry.release_aab.sha256 ||
              identity.function !== entry.function
            ) {
              throw new Error(
                `completed shard identity mismatch: ${shardDir}`,
              );
            }
            verifyBenchContract(retained, entry.function);
            console.log(
              `[skip completed] ${entry.function} on ${device.label}`,
            );
            continue;
          }
          throw new Error(
            `successful status lacks bench-report.json: ${shardDir}`,
          );
        }
        if (status.outcome === "failed" && !options.retryFailed) {
          console.log(
            `[skip failed; pass --retry-failed] ${entry.function} on ${device.label}`,
          );
          continue;
        }
      }
      const startedAt = new Date().toISOString();
      await writeJsonAtomic(join(shardDir, "request.json"), {
        schema: "provekit.android-browserstack-appium-request.v1",
        requested_at: startedAt,
        source_sha: manifest.source_sha,
        source_manifest: options.manifest,
        source_manifest_sha256: await sha256File(options.manifest),
        function: entry.function,
        device,
        artifact_sha256: entry.release_aab.sha256,
        artifact_build_profile: "release",
        signed: entry.signed,
        warmup: 1,
        iterations: 5,
        credential_source: "env",
        paid_confirmation: true,
      });
      console.log(`[run] ${entry.function} on ${device.label}`);
      try {
        const completed = await runSession(
          entry,
          manifest.source_sha,
          device,
          options,
          authorization,
          username,
          accessKey,
          shardDir,
        );
        await writeJsonAtomic(statusPath, {
          schema: "provekit.android-browserstack-appium-status.v1",
          source_sha: manifest.source_sha,
          artifact_sha256: entry.release_aab.sha256,
          function: entry.function,
          device: device.label,
          outcome: "success",
          session_id: completed.sessionId,
          build_id: completed.buildId,
          started_at: startedAt,
          finished_at: new Date().toISOString(),
          result: relative(options.outputDir, join(shardDir, "result.json")),
          bench_report: relative(
            options.outputDir,
            join(shardDir, "bench-report.json"),
          ),
        });
      } catch (error) {
        const retainedSessionPath = join(shardDir, "session.json");
        const retainedSession = (await Bun.file(retainedSessionPath).exists())
          ? ((await Bun.file(retainedSessionPath).json()) as JsonObject)
          : {};
        await writeJsonAtomic(statusPath, {
          schema: "provekit.android-browserstack-appium-status.v1",
          source_sha: manifest.source_sha,
          artifact_sha256: entry.release_aab.sha256,
          function: entry.function,
          device: device.label,
          outcome: "failed",
          session_id:
            typeof retainedSession.session_id === "string"
              ? retainedSession.session_id
              : null,
          started_at: startedAt,
          finished_at: new Date().toISOString(),
          error:
            error instanceof Error ? error.message : "unknown Appium failure",
        });
        console.error(
          `[failed] ${entry.function} on ${device.label}: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
      await writeIndex(
        options.outputDir,
        manifest.source_sha,
        options.manifest,
      );
    }
  }
  await writeIndex(options.outputDir, manifest.source_sha, options.manifest);
}

await main();
