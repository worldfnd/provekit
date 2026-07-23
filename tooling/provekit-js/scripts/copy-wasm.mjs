import { cp, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const packageRoot = resolve(import.meta.dirname, "..");
const source = resolve(
  process.env.PROVEKIT_WASM_SOURCE_DIR || resolve(packageRoot, "../provekit-wasm/pkg"),
);
const destination = resolve(packageRoot, "dist/wasm");
const runtimeAssets = resolve(packageRoot, "runtime-assets");
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
  const withGlueImport = original
    .replace(
      "({ init, receiver }) =>",
      "({ init, receiver, glueUrl }) =>",
    )
    .replace(
      "import('../../..')",
      "import(/* @vite-ignore */ glueUrl)",
    );
  const withWorkerSetter = withGlueImport.replace(
    "let _workers;",
    `let _workers;
let configuredWorkerUrl;
let configuredWorkerGlueUrl;

export function setWorkerUrl(url) {
  configuredWorkerUrl = url;
}

export function setWorkerGlueUrl(url) {
  configuredWorkerGlueUrl = url;
}`,
  );
  const withGlueUrl = withWorkerSetter.replace(
    "receiver: builder.receiver()",
    "receiver: builder.receiver(),\n    glueUrl: configuredWorkerGlueUrl",
  );
  const patched = withGlueUrl.replace(
    "new Worker(new URL('./workerHelpers.js', import.meta.url), {",
    "new Worker(configuredWorkerUrl ?? new URL('./workerHelpers.js', import.meta.url), {",
  );
  if (
    patched === original ||
    !patched.includes("configuredWorkerUrl") ||
    !patched.includes("configuredWorkerGlueUrl") ||
    !patched.includes("import(/* @vite-ignore */ glueUrl)")
  ) {
    throw new Error(`Could not patch the rayon worker glue import in ${helper}`);
  }
  await writeFile(helper, patched);

  const threadedGlue = resolve(destination, "threaded/provekit_wasm.js");
  const glue = await readFile(threadedGlue, "utf8");
  const patchedGlue = glue.replace(
    "import { startWorkers } from './snippets/",
    "import { startWorkers, setWorkerGlueUrl, setWorkerUrl } from './snippets/",
  );
  if (patchedGlue === glue) {
    throw new Error(`Could not expose the rayon worker URL setter in ${threadedGlue}`);
  }
  await writeFile(
    threadedGlue,
    `${patchedGlue}\nsetWorkerGlueUrl(import.meta.url);\n\nexport { setWorkerUrl };\n`,
  );
}

await cp(
  resolve(runtimeAssets, "provekit_wasm_worker.js"),
  resolve(destination, "threaded/provekit_wasm_worker.js"),
);
