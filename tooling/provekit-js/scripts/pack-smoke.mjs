import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const packageRoot = resolve(import.meta.dirname, "..");
const output = execFileSync("npm", ["pack", "--json", "--ignore-scripts"], {
  cwd: packageRoot,
  encoding: "utf8",
});
const [{ filename, files }] = JSON.parse(output);
const paths = new Set(files.map((entry) => entry.path));
for (const required of [
  "dist/index.js",
  "dist/index.d.ts",
  "dist/wasm/single/provekit_wasm.js",
  "dist/wasm/single/provekit_wasm_bg.wasm",
  "dist/wasm/threaded/provekit_wasm.js",
  "dist/wasm/threaded/provekit_wasm_bg.wasm",
]) {
  if (!paths.has(required)) throw new Error(`Packed package is missing ${required}`);
}

const temporary = await mkdtemp(join(tmpdir(), "worldcoin-provekit-pack-"));
try {
  const tarball = resolve(packageRoot, filename);
  execFileSync("npm", ["init", "-y"], { cwd: temporary, stdio: "ignore" });
  execFileSync("npm", ["install", "--ignore-scripts", tarball], { cwd: temporary, stdio: "ignore" });
  await writeFile(
    join(temporary, "smoke.mjs"),
    'import { initProveKit, Proof, ProveKitError } from "@worldcoin/provekit";\nif (!initProveKit || !Proof || !ProveKitError) process.exit(1);\n',
  );
  execFileSync(process.execPath, ["smoke.mjs"], { cwd: temporary, stdio: "inherit" });
  await readFile(join(temporary, "node_modules/@worldcoin/provekit/dist/wasm/single/provekit_wasm_bg.wasm"));
  await readFile(join(temporary, "node_modules/@worldcoin/provekit/dist/wasm/threaded/provekit_wasm_bg.wasm"));
  await rm(tarball, { force: true });
} finally {
  await rm(temporary, { recursive: true, force: true });
}
