import { chromium } from "playwright-core";
import { startServer } from "./server";

const server = startServer();
const executablePath =
  process.env.CHROME_PATH ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const browser = await chromium.launch({ executablePath, headless: true });

try {
  const page = await browser.newPage();
  await page.goto(`${server.url}?autorun=1&warmup=0&iterations=1`);
  await page.waitForFunction(
    () => ["complete", "error"].includes(window.__MOBENCH_STATE__?.status),
    undefined,
    { timeout: 10 * 60 * 1000 },
  );
  const state = await page.evaluate(() => window.__MOBENCH_STATE__);
  if (state.status !== "complete") throw new Error(state.error ?? "browser benchmark failed");
  console.log(JSON.stringify(state.result, null, 2));
} finally {
  await browser.close();
  server.stop(true);
}
