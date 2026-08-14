#!/usr/bin/env bun

import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const [ipaArg, outputArg, countArg = "6"] = process.argv.slice(2);
if (!ipaArg || !outputArg) {
  throw new Error("usage: run-ios-browserstack-appium.ts <app.ipa> <output-dir> [count]");
}
const username = process.env.BROWSERSTACK_USERNAME;
const accessKey = process.env.BROWSERSTACK_ACCESS_KEY;
if (!username || !accessKey) throw new Error("BrowserStack credentials are required");
const ipa = resolve(ipaArg);
const output = resolve(outputArg);
const count = Number(countArg);
if (!Number.isInteger(count) || count < 1) throw new Error("count must be positive");
await mkdir(output, { recursive: true });

const authorization = `Basic ${Buffer.from(`${username}:${accessKey}`).toString("base64")}`;
let appUrl = process.env.BROWSERSTACK_APP_URL;
if (!appUrl) {
  const upload = new FormData();
  upload.set("file", Bun.file(ipa));
  const uploaded = await fetch("https://api-cloud.browserstack.com/app-automate/upload", {
    method: "POST",
    headers: { authorization },
    body: upload,
  });
  if (!uploaded.ok) throw new Error(`BrowserStack app upload failed: HTTP ${uploaded.status}`);
  appUrl = (await uploaded.json() as { app_url: string }).app_url;
}
await Bun.write(resolve(output, "upload.json"), `${JSON.stringify({ app_url: appUrl }, null, 2)}\n`);

async function webdriver(path: string, init?: RequestInit) {
  const response = await fetch(`https://hub-cloud.browserstack.com/wd/hub${path}`, {
    ...init,
    headers: { authorization, "content-type": "application/json", ...(init?.headers ?? {}) },
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(`WebDriver ${path} failed: HTTP ${response.status} ${JSON.stringify(body)}`);
  return body;
}

for (let index = 0; index < count; index++) {
  const created = await webdriver("/session", {
    method: "POST",
    body: JSON.stringify({
      capabilities: {
        alwaysMatch: {
          platformName: "iOS",
          "appium:app": appUrl,
          "bstack:options": {
            deviceName: "iPhone SE 2022",
            osVersion: "15",
            projectName: "ProveKit V1 input-to-proof recovery",
            buildName: "iPhone Circom registration cold Appium",
            sessionName: `registration cold ${index}`,
            deviceLogs: true,
            appProfiling: true,
            idleTimeout: 900,
          },
        },
      },
    }),
  });
  const sessionId = created.value?.sessionId ?? created.sessionId;
  if (!sessionId) throw new Error(`BrowserStack returned no session id: ${JSON.stringify(created)}`);
  const evidence = { index, session_id: sessionId, app_url: appUrl };
  await Bun.write(resolve(output, `session-${index}.json`), `${JSON.stringify(evidence, null, 2)}\n`);
  try {
    const deadline = Date.now() + 7_200_000;
    let report: unknown;
    while (Date.now() < deadline) {
      const found = await webdriver(`/session/${sessionId}/elements`, {
        method: "POST",
        body: JSON.stringify({ using: "accessibility id", value: "benchmarkReportJSON" }),
      });
      const element = found.value?.[0];
      const elementId = element?.["element-6066-11e4-a52e-4f735466cecf"] ?? element?.ELEMENT;
      if (elementId) {
        for (const attribute of ["value", "label"]) {
          const value = await webdriver(`/session/${sessionId}/element/${elementId}/attribute/${attribute}`);
          if (typeof value.value === "string" && value.value.startsWith("{")) {
            report = JSON.parse(value.value);
            break;
          }
        }
      }
      if (report) break;
      await Bun.sleep(5_000);
    }
    if (!report) throw new Error("timed out waiting for benchmarkReportJSON");
    await Bun.write(resolve(output, `report-${index}.json`), `${JSON.stringify(report, null, 2)}\n`);
    await webdriver(`/session/${sessionId}/execute/sync`, {
      method: "POST",
      body: JSON.stringify({ script: "browserstack_executor: {\"action\": \"setSessionStatus\", \"arguments\": {\"status\": \"passed\", \"reason\": \"structured Mobench report captured\"}}", args: [] }),
    }).catch(() => null);
  } finally {
    await webdriver(`/session/${sessionId}`, { method: "DELETE", body: "{}" }).catch(() => null);
  }
}
