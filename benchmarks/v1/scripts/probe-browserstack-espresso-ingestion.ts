import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const username = process.env.BROWSERSTACK_USERNAME;
const accessKey = process.env.BROWSERSTACK_ACCESS_KEY;
if (!username || !accessKey) {
  throw new Error(
    "BROWSERSTACK_USERNAME and BROWSERSTACK_ACCESS_KEY are required",
  );
}

const timeoutMs = Number.parseInt(
  process.env.V1_BROWSERSTACK_PROBE_TIMEOUT_MS ?? "60000",
  10,
);
if (!Number.isInteger(timeoutMs) || timeoutMs < 10_000 || timeoutMs > 600_000) {
  throw new Error(
    "V1_BROWSERSTACK_PROBE_TIMEOUT_MS must be between 10000 and 600000",
  );
}

const transport = process.env.V1_BROWSERSTACK_PROBE_TRANSPORT ?? "url";
if (transport !== "url" && transport !== "file") {
  throw new Error(
    "V1_BROWSERSTACK_PROBE_TRANSPORT must be either url or file",
  );
}

const outputDirectory = resolve(
  Bun.argv[2] ??
    "benchmarks/v1/results/run-30041758043/browserstack-ingestion-diagnostics/heartbeats",
);
await mkdir(outputDirectory, { recursive: true });

const startedAt = new Date();
const stamp = startedAt
  .toISOString()
  .replaceAll(/[-:.]/g, "")
  .replace("Z", "Z");
const customId = `pkv1-heartbeat-control-${stamp.toLowerCase()}`;
const sampleUrl =
  "https://www.browserstack.com/app-automate/sample-apps/android/WikipediaSample.apk";
const api = "https://api-cloud.browserstack.com/app-automate/espresso/v2";
const authorization = `Basic ${Buffer.from(`${username}:${accessKey}`).toString("base64")}`;
const expectedSampleBytes = 20_373_104;
const expectedSampleSha256 =
  "622d394215af0379aa44b7d8b92ac3407c7519cd0db239a0e6dfc86ea734cb79";

async function jsonRequest(
  url: string,
): Promise<{ status: number; payload: unknown }> {
  const response = await fetch(url, {
    headers: { Authorization: authorization },
  });
  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { non_json_response_bytes: Buffer.byteLength(text) };
    }
  }
  return { status: response.status, payload };
}

function matchingApps(payload: unknown): unknown[] {
  const items = Array.isArray(payload)
    ? payload
    : payload &&
        typeof payload === "object" &&
        "apps" in payload &&
        Array.isArray((payload as { apps: unknown }).apps)
      ? (payload as { apps: unknown[] }).apps
      : [];
  return items.filter(
    (item) =>
      item &&
      typeof item === "object" &&
      "custom_id" in item &&
      (item as { custom_id: unknown }).custom_id === customId,
  );
}

let sampleBytes: Uint8Array | null = null;
if (transport === "file") {
  const sampleResponse = await fetch(sampleUrl);
  if (!sampleResponse.ok) {
    throw new Error(
      `control APK download failed: HTTP ${sampleResponse.status}`,
    );
  }
  sampleBytes = new Uint8Array(await sampleResponse.arrayBuffer());
  const sampleSha256 = createHash("sha256").update(sampleBytes).digest("hex");
  if (
    sampleBytes.byteLength !== expectedSampleBytes ||
    sampleSha256 !== expectedSampleSha256
  ) {
    throw new Error("BrowserStack control APK no longer matches its pin");
  }
}

const before = await jsonRequest(
  `${api}/apps?custom_id=${encodeURIComponent(customId)}`,
);
if (before.status !== 200 || matchingApps(before.payload).length !== 0) {
  throw new Error(
    "control custom ID lookup was not an authenticated cache miss",
  );
}

const form = new FormData();
if (transport === "url") {
  form.set("url", sampleUrl);
} else {
  form.set(
    "file",
    new Blob([sampleBytes!], {
      type: "application/vnd.android.package-archive",
    }),
    "WikipediaSample.apk",
  );
}
form.set("custom_id", customId);

let uploadStatus: number | null = null;
let uploadResponseBytes = 0;
let uploadOutcome = "unknown";
let uploadErrorName: string | null = null;
const uploadStarted = performance.now();
try {
  const response = await fetch(`${api}/app`, {
    method: "POST",
    headers: { Authorization: authorization },
    body: form,
    signal: AbortSignal.timeout(timeoutMs),
  });
  uploadStatus = response.status;
  const responseText = await response.text();
  uploadResponseBytes = Buffer.byteLength(responseText);
  uploadOutcome = response.ok ? "completed" : "http_error";
} catch (error) {
  uploadErrorName = error instanceof Error ? error.name : "unknown";
  uploadOutcome =
    uploadErrorName === "TimeoutError" ? "client_timeout" : "request_error";
}
const elapsedSeconds = (performance.now() - uploadStarted) / 1000;

const after = await jsonRequest(
  `${api}/apps?custom_id=${encodeURIComponent(customId)}`,
);
const matches = after.status === 200 ? matchingApps(after.payload) : [];
const handle =
  matches.length === 1 &&
  matches[0] &&
  typeof matches[0] === "object" &&
  "app_url" in matches[0] &&
  typeof (matches[0] as { app_url: unknown }).app_url === "string"
    ? (matches[0] as { app_url: string }).app_url
    : null;

const summary = {
  schema: "provekit.browserstack-ingestion-heartbeat.v1",
  started_at: startedAt.toISOString(),
  completed_at: new Date().toISOString(),
  credential_source: "environment",
  credentials_retained: false,
  endpoint: `${api}/app`,
  custom_id: customId,
  control_artifact: {
    description: "BrowserStack WikipediaSample.apk",
    source_url: sampleUrl,
    expected_bytes: expectedSampleBytes,
    expected_sha256: expectedSampleSha256,
    transport,
  },
  timeout_ms: timeoutMs,
  upload: {
    elapsed_seconds: elapsedSeconds,
    http_status: uploadStatus,
    response_bytes: uploadResponseBytes,
    outcome: uploadOutcome,
    error_name: uploadErrorName,
  },
  final_lookup: {
    http_status: after.status,
    match_count: matches.length,
    handle,
  },
  diagnosis:
    uploadOutcome === "client_timeout" &&
    after.status === 200 &&
    matches.length === 0
      ? "artifact_processing_stalled"
      : uploadOutcome === "completed" && handle !== null
        ? "healthy"
        : "indeterminate",
  ingestion_recovered: uploadOutcome === "completed" && handle !== null,
};

const outputPath = resolve(outputDirectory, `${stamp}-summary.json`);
await Bun.write(outputPath, `${JSON.stringify(summary, null, 2)}\n`);
console.log(outputPath);
console.log(
  summary.ingestion_recovered
    ? "ingestion_recovered=true"
    : "ingestion_recovered=false",
);
