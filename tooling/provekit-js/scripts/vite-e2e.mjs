import { execFileSync, spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { chromium } from "playwright";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const fixtureRoot = resolve(packageRoot, "tests/vite-consumer");
const currentArtifacts = resolve(repositoryRoot, "playground/wasm-demo/artifacts/sha256");

function run(command, args, cwd) {
  return execFileSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
}

async function availablePort() {
  const server = createServer();
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not allocate a Vite test port");
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return address.port;
}

async function waitForServer(url, child) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Vite exited with code ${child.exitCode}`);
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // The server is still starting.
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error("Timed out waiting for the packed-package Vite consumer");
}

async function withTimeout(promise, message, timeoutMs = 30_000) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error(message())), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function allowedRequest(url, origin) {
  const parsed = new URL(url);
  if (parsed.origin !== origin) return false;
  if (parsed.search !== "") {
    const cacheKey = parsed.searchParams.get("v");
    const viteCacheQuery =
      parsed.pathname.startsWith("/node_modules/.vite/deps/") &&
      parsed.searchParams.size === 1 &&
      cacheKey !== null &&
      /^[a-f0-9]+$/i.test(cacheKey);
    const viteStaticAssetQuery =
      parsed.pathname.endsWith(".wasm") &&
      parsed.searchParams.size === 2 &&
      parsed.searchParams.has("import") &&
      parsed.searchParams.get("import") === "" &&
      parsed.searchParams.has("url") &&
      parsed.searchParams.get("url") === "";
    if (!viteCacheQuery && !viteStaticAssetQuery) return false;
  }
  return [
    /^\/@vite\/client$/,
    /^\/node_modules\/vite\/dist\/client\/env\.mjs$/,
    /^\/artifacts\/(?:prover\.pkp|verifier\.pkv|inputs\.json)$/,
    /^\/node_modules\/.vite\/deps\//,
    /^\/node_modules\/@worldcoin\/provekit\/dist\/wasm\//,
    /^\/node_modules\/@noir-lang\/(?:noirc_abi|acvm_js)\/web\/.*\.wasm$/,
    /^\/assets\//,
  ].some((pattern) => pattern.test(parsed.pathname));
}

function allowedWebSocket(url, origin, label) {
  if (label !== "development") return false;
  const parsed = new URL(url);
  const expected = new URL(origin);
  const token = parsed.searchParams.get("token");
  return parsed.protocol === "ws:" &&
    parsed.hostname === expected.hostname &&
    parsed.port === expected.port &&
    parsed.pathname === "/" &&
    parsed.searchParams.size === 1 &&
    token !== null &&
    /^[A-Za-z0-9_-]+$/.test(token);
}

async function startVite(temporary, command = []) {
  const port = await availablePort();
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(
    resolve(temporary, "node_modules/.bin/vite"),
    [...command, "--host", "127.0.0.1", "--port", String(port), "--strictPort"],
    { cwd: temporary, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  child.stdout.on("data", (chunk) => { output += String(chunk); });
  child.stderr.on("data", (chunk) => { output += String(chunk); });
  await waitForServer(origin, child).catch((error) => {
    throw new Error(`${error.message}\n${output}`);
  });
  return { child, origin };
}

async function runBrowserAcceptance(browser, origin, label) {
  for (const setting of [false, "auto"]) {
    const page = await browser.newPage();
    const requests = [];
    const webSockets = [];
    const diagnostics = [];
    page.on("console", (message) => diagnostics.push(`console:${message.type()}:${message.text()}`));
    page.on("pageerror", (error) => diagnostics.push(`pageerror:${error.message}`));
    page.on("requestfailed", (request) => diagnostics.push(`requestfailed:${request.url()}:${request.failure()?.errorText}`));
    page.on("response", (response) => {
      if (response.status() >= 400) diagnostics.push(`response:${response.status()}:${response.url()}`);
    });
    await page.goto(origin);
    await page.waitForFunction(() => typeof window.runProveKit === "function");
    page.on("websocket", (socket) => webSockets.push(socket.url()));
    page.on("request", (request) => {
      requests.push({
        url: request.url(),
        method: request.method(),
        postData: request.postData(),
      });
    });
    const result = await withTimeout(
      page.evaluate((threadSetting) => window.runProveKit(threadSetting), setting),
      () => `Browser acceptance timed out: ${diagnostics.join(" | ")}`,
    );
    if (!result.valid || result.proofBytes <= 0) throw new Error(`Invalid proof result: ${JSON.stringify(result)}`);
    if (result.legacyErrorCode !== "ARTIFACT_VERSION") {
      throw new Error(`Legacy artifact was not rejected: ${JSON.stringify(result)}`);
    }
    const expectedMode = setting === false ? "single" : "threaded";
    if (result.mode !== expectedMode) throw new Error(`Expected ${expectedMode}: ${JSON.stringify(result)}`);
    for (const request of requests) {
      if (request.method !== "GET" || request.postData !== null || !allowedRequest(request.url, origin)) {
        throw new Error(`Unexpected proof-phase request: ${JSON.stringify(request)}`);
      }
    }
    const unexpectedWebSockets = webSockets.filter((url) => !allowedWebSocket(url, origin, label));
    if (unexpectedWebSockets.length !== 0) {
      throw new Error(`Unexpected proof-phase WebSocket: ${JSON.stringify(unexpectedWebSockets)}`);
    }
    console.log(`VITE_ACCEPTANCE ${JSON.stringify({ vite: label, ...result })}`);
    await page.close();
  }
}

const temporary = await mkdtemp(join(tmpdir(), "provekit-vite-consumer-"));
let tarball;
const viteProcesses = [];
let browser;
try {
  const [{ filename }] = JSON.parse(run("npm", ["pack", "--json", "--ignore-scripts"], packageRoot));
  tarball = resolve(packageRoot, filename);
  await cp(fixtureRoot, temporary, { recursive: true });
  await mkdir(resolve(temporary, "public/artifacts"), { recursive: true });
  for (const file of ["prover.pkp", "verifier.pkv", "inputs.json"]) {
    await cp(resolve(currentArtifacts, file), resolve(temporary, "public/artifacts", file));
  }
  run(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball, "vite@7.2.7"],
    temporary,
  );

  browser = await chromium.launch({ headless: true });
  const development = await startVite(temporary, ["--force"]);
  viteProcesses.push(development.child);
  await runBrowserAcceptance(browser, development.origin, "development");
  development.child.kill("SIGTERM");

  run(resolve(temporary, "node_modules/.bin/vite"), ["build"], temporary);
  const preview = await startVite(temporary, ["preview"]);
  viteProcesses.push(preview.child);
  await runBrowserAcceptance(browser, preview.origin, "preview");
} finally {
  await browser?.close();
  for (const vite of viteProcesses) {
    if (vite.exitCode === null) vite.kill("SIGTERM");
  }
  await rm(temporary, { recursive: true, force: true });
  if (tarball) await rm(tarball, { force: true });
}
