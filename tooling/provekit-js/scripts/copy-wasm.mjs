import { cp, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const packageRoot = resolve(import.meta.dirname, "..");
const source = resolve(
  process.env.PROVEKIT_WASM_SOURCE_DIR || resolve(packageRoot, "../provekit-wasm/pkg"),
);
const destination = resolve(packageRoot, "dist/wasm");
const required = [
  "provekit_wasm.js",
  "provekit_wasm.d.ts",
  "provekit_wasm_bg.wasm",
  "provekit_wasm_bg.wasm.d.ts",
];

for (const variant of ["single", "threaded"]) {
  for (const file of required) {
    try {
      await stat(resolve(source, variant, file));
    } catch {
      throw new Error(`Missing ${resolve(source, variant, file)}; run npm run build:wasm first`);
    }
  }
}

await rm(destination, { recursive: true, force: true });
await mkdir(resolve(packageRoot, "dist"), { recursive: true });
await cp(source, destination, { recursive: true, force: true });

const snippets = resolve(destination, "threaded/snippets");
for (const entry of await readdir(snippets, { withFileTypes: true })) {
  if (!entry.isDirectory() || !entry.name.startsWith("wasm-bindgen-rayon-")) continue;
  const helper = resolve(snippets, entry.name, "src/workerHelpers.js");
  const original = await readFile(helper, "utf8");
  const patched = original.replace(
    "import('../../..')",
    "import('../../../provekit_wasm.js')",
  );
  if (patched === original) {
    throw new Error(`Could not patch the rayon worker glue import in ${helper}`);
  }
  await writeFile(helper, patched);
}
