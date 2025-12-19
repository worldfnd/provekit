#!/usr/bin/env node
/**
 * Simple HTTP server for the web demo with Cross-Origin Isolation.
 *
 * Serves static files with proper MIME types and required headers for:
 * - SharedArrayBuffer (needed for wasm-bindgen-rayon thread pool)
 * - Cross-Origin Isolation (COOP + COEP headers)
 */

import { createServer } from "http";
import { readFile, stat } from "fs/promises";
import { extname, join, resolve } from "path";
import { fileURLToPath } from "url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const ROOT = resolve(__dirname, "..");
const START_PORT = parseInt(process.env.PORT || "8080");

const MIME_TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".wasm": "application/wasm",
  ".toml": "text/plain",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
};

async function serveFile(res, filePath) {
  try {
    const data = await readFile(filePath);
    const ext = extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";

    res.writeHead(200, {
      "Content-Type": contentType,
      "Access-Control-Allow-Origin": "*",
      // Cross-Origin Isolation headers required for SharedArrayBuffer
      // These enable wasm-bindgen-rayon's Web Worker-based parallelism
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    });
    res.end(data);
  } catch (err) {
    if (err.code === "ENOENT") {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found");
    } else {
      console.error(err);
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Internal Server Error");
    }
  }
}

async function handleRequest(req, res) {
  let urlPath = req.url.split("?")[0];

  // Default to index.html
  if (urlPath === "/") {
    urlPath = "/index.html";
  }

  const filePath = join(ROOT, urlPath);

  // Security: prevent directory traversal
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("Forbidden");
    return;
  }

  // Check if it's a directory and serve index.html
  try {
    const stats = await stat(filePath);
    if (stats.isDirectory()) {
      await serveFile(res, join(filePath, "index.html"));
    } else {
      await serveFile(res, filePath);
    }
  } catch (err) {
    if (err.code === "ENOENT") {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found");
    } else {
      console.error(err);
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Internal Server Error");
    }
  }
}

async function startServer(port, maxAttempts = 10) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const currentPort = port + attempt;
    try {
      await new Promise((resolve, reject) => {
        const server = createServer(handleRequest);
        server.once("error", reject);
        server.listen(currentPort, () => {
          console.log(`\n🌐 ProveKit WASM Web Demo (with parallelism)`);
          console.log(`   Server running at http://localhost:${currentPort}`);
          console.log(`\n   Cross-Origin Isolation: ENABLED`);
          console.log(`   SharedArrayBuffer: AVAILABLE`);
          console.log(`   Thread pool: SUPPORTED`);
          console.log(`\n   Open the URL above in your browser to run the demo.`);
          console.log(`   Press Ctrl+C to stop.\n`);
          resolve();
        });
      });
      return; // Success
    } catch (err) {
      if (err.code === "EADDRINUSE") {
        console.log(`Port ${currentPort} is in use, trying ${currentPort + 1}...`);
      } else {
        throw err;
      }
    }
  }
  console.error(`Could not find an available port after ${maxAttempts} attempts`);
  process.exit(1);
}

startServer(START_PORT);
