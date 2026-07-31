#!/usr/bin/env bun

import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "../../..");
const path = resolve(
  process.env.V1_WEBAUTHN_ZKEY ??
    resolve(
      repoRoot,
      "target/v1-benchmarks/groth16/webauthn/webauthn_default_benchmark.zkey",
    ),
);
const artifact = Bun.file(path);
if (!(await artifact.exists())) throw new Error(`missing WebAuthn zkey: ${path}`);
const port = Number.parseInt(process.env.PORT ?? "18080", 10);

Bun.serve({
  port,
  fetch(request) {
    return new Response(request.method === "HEAD" ? null : artifact, {
      headers: {
        "content-type": "application/octet-stream",
        "content-length": String(artifact.size),
        "cache-control": "public, max-age=3600",
      },
    });
  },
});

console.log(`Serving ${artifact.size} bytes on http://127.0.0.1:${port}`);
await new Promise(() => {});
