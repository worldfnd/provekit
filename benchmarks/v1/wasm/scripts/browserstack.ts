import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { resolve, sep } from "node:path";
import matrix from "../browser-matrix.json";
import { startServer } from "./server";

interface BrowserEnvironment {
  id: string;
  os: string;
  os_version: string;
  device?: string;
  browser: string;
  execution: string;
  real_mobile: boolean;
}

interface BundleManifest {
  artifacts: Array<{
    path: string;
    bytes: number;
    sha256: string;
    mime_type: string;
  }>;
  totals: Record<string, number>;
}

interface WebDriverResponse<T> {
  value?: T & {
    error?: string;
    message?: string;
  };
  sessionId?: string;
}

const wasmRoot = resolve(new URL("..", import.meta.url).pathname);
const repositoryRoot = resolve(wasmRoot, "../../..");
const distRoot = resolve(wasmRoot, "dist");
const hub = "https://hub-cloud.browserstack.com/wd/hub";

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function expectedMimeType(path: string): string {
  if (path.endsWith(".html")) return "text/html; charset=utf-8";
  if (path.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (path.endsWith(".json")) return "application/json; charset=utf-8";
  if (path.endsWith(".wasm")) return "application/wasm";
  return "application/octet-stream";
}

async function verifyStaticBundle() {
  const manifestPath = resolve(distRoot, "manifest.json");
  const manifestBytes = new Uint8Array(await readFile(manifestPath));
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as BundleManifest;
  let totalBytes = 0;

  for (const artifact of manifest.artifacts) {
    const artifactPath = resolve(repositoryRoot, artifact.path);
    if (artifactPath !== distRoot && !artifactPath.startsWith(`${distRoot}${sep}`)) {
      throw new Error(`manifest path escapes dist: ${artifact.path}`);
    }
    const metadata = await lstat(artifactPath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`manifest artifact must be a regular non-symlink file: ${artifact.path}`);
    }
    const canonicalPath = await realpath(artifactPath);
    if (canonicalPath !== distRoot && !canonicalPath.startsWith(`${distRoot}${sep}`)) {
      throw new Error(`manifest artifact resolves outside dist: ${artifact.path}`);
    }
    const bytes = new Uint8Array(await readFile(artifactPath));
    if (bytes.byteLength !== artifact.bytes) {
      throw new Error(`size mismatch for ${artifact.path}`);
    }
    if (sha256(bytes) !== artifact.sha256) {
      throw new Error(`SHA-256 mismatch for ${artifact.path}`);
    }
    if (artifact.mime_type !== expectedMimeType(artifact.path)) {
      throw new Error(`MIME type mismatch for ${artifact.path}`);
    }
    totalBytes += bytes.byteLength;
  }

  const declaredTotal = Object.values(manifest.totals).reduce((sum, value) => sum + value, 0);
  if (totalBytes !== declaredTotal) {
    throw new Error(`manifest total mismatch: measured ${totalBytes}, declared ${declaredTotal}`);
  }

  return {
    manifest_sha256: sha256(manifestBytes),
    total_bytes: totalBytes,
    artifact_count: manifest.artifacts.length,
  };
}

async function webdriver<T>(
  path: string,
  authorization: string,
  method: "POST" | "DELETE",
  body?: unknown,
): Promise<WebDriverResponse<T>> {
  const response = await fetch(`${hub}${path}`, {
    method,
    headers: {
      Authorization: authorization,
      "Content-Type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = (await response.json()) as WebDriverResponse<T>;
  if (!response.ok || payload.value?.error) {
    throw new Error(
      `WebDriver ${method} ${path} failed: ${payload.value?.message ?? response.statusText}`,
    );
  }
  return payload;
}

function sourceRevision(): string {
  const result = Bun.spawnSync(["git", "-C", repositoryRoot, "rev-parse", "HEAD"]);
  if (result.exitCode !== 0) throw new Error("could not resolve source revision");
  return result.stdout.toString().trim();
}

function resolvedEnvironment(
  capabilities: Record<string, unknown>,
  requested: BrowserEnvironment,
  osVersion: string,
) {
  const browserVersion =
    typeof capabilities.browserVersion === "string" ? capabilities.browserVersion : null;
  return {
    browser_name:
      typeof capabilities.browserName === "string"
        ? capabilities.browserName
        : requested.browser,
    browser_version: browserVersion,
    device_name:
      typeof capabilities.deviceName === "string"
        ? capabilities.deviceName
        : requested.device ?? "unknown",
    os_version:
      typeof capabilities.osVersion === "string" ? capabilities.osVersion : osVersion,
    real_mobile: true,
  };
}

const requestedId = Bun.argv[2];
if (!requestedId) {
  throw new Error("usage: bun run browserstack -- <environment-id|--verify-bundle>");
}
if (requestedId === "--verify-bundle") {
  console.log(JSON.stringify(await verifyStaticBundle(), null, 2));
  process.exit(0);
}

const requested = (matrix.environments as BrowserEnvironment[]).find(
  (environment) => environment.id === requestedId,
);
if (!requested) throw new Error(`unknown browser environment: ${requestedId}`);
if (!requested.real_mobile || requested.execution !== "single-thread" || !requested.device) {
  throw new Error(`${requestedId} is not a real-mobile single-thread environment`);
}

const username = requiredEnvironment("BROWSERSTACK_USERNAME");
const accessKey = requiredEnvironment("BROWSERSTACK_ACCESS_KEY");
const localIdentifier = requiredEnvironment("BROWSERSTACK_LOCAL_IDENTIFIER");
const osVersion =
  process.env.BROWSERSTACK_OS_VERSION ??
  (requested.os_version.startsWith("set-via-") ? undefined : requested.os_version);
if (!osVersion) {
  throw new Error(
    "BROWSERSTACK_OS_VERSION is required; resolve and freeze a currently available device/OS pair",
  );
}

const warmup = Number.parseInt(process.env.MOBENCH_WARMUP ?? "1", 10);
const iterations = Number.parseInt(process.env.MOBENCH_ITERATIONS ?? "5", 10);
if (!Number.isInteger(warmup) || warmup < 0 || warmup > 10) {
  throw new Error("MOBENCH_WARMUP must be an integer from 0 to 10");
}
if (!Number.isInteger(iterations) || iterations < 1 || iterations > 20) {
  throw new Error("MOBENCH_ITERATIONS must be an integer from 1 to 20");
}

const bundle = await verifyStaticBundle();
const server = startServer();
const authorization = `Basic ${Buffer.from(`${username}:${accessKey}`).toString("base64")}`;
let sessionId: string | undefined;

try {
  const created = await webdriver<{
    sessionId?: string;
    capabilities?: Record<string, unknown>;
  }>("/session", authorization, "POST", {
    capabilities: {
      alwaysMatch: {
        browserName: requested.browser.toLowerCase(),
        "bstack:options": {
          userName: username,
          accessKey,
          osName: requested.os,
          osVersion,
          deviceName: requested.device,
          realMobile: true,
          local: true,
          localIdentifier,
          projectName: "ProveKit V1 benchmarks",
          buildName: `provekit-v1-${sourceRevision().slice(0, 12)}`,
          sessionName: `${requested.id} WebAuthn assertion`,
        },
      },
    },
  });
  sessionId = created.value?.sessionId ?? created.sessionId;
  if (!sessionId) throw new Error("BrowserStack did not return a session ID");

  const capabilities = created.value?.capabilities ?? {};
  await webdriver(`/session/${sessionId}/url`, authorization, "POST", {
    url: `http://localhost:${new URL(server.url).port}/?autorun=1&warmup=${warmup}&iterations=${iterations}`,
  });

  const deadline = Date.now() + 15 * 60 * 1000;
  let state: { status?: string; result?: Record<string, unknown>; error?: string } | undefined;
  while (Date.now() < deadline) {
    const response = await webdriver<{
      status?: string;
      result?: Record<string, unknown>;
      error?: string;
    }>(`/session/${sessionId}/execute/sync`, authorization, "POST", {
      script: "return window.__MOBENCH_STATE__ || null",
      args: [],
    });
    state = response.value;
    if (state?.status === "complete" || state?.status === "error") break;
    await Bun.sleep(1_000);
  }

  if (state?.status !== "complete" || !state.result) {
    throw new Error(state?.error ?? "BrowserStack browser benchmark timed out");
  }

  console.log(
    JSON.stringify(
      {
        schema_version: 1,
        source_revision: sourceRevision(),
        session_id: sessionId,
        requested_environment: {
          ...requested,
          os_version: osVersion,
        },
        resolved_environment: resolvedEnvironment(capabilities, requested, osVersion),
        static_bundle: bundle,
        benchmark_result: state.result,
      },
      null,
      2,
    ),
  );
} finally {
  if (sessionId) {
    await webdriver(`/session/${sessionId}`, authorization, "DELETE").catch(() => undefined);
  }
  server.stop(true);
}
