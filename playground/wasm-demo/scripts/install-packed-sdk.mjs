import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { resolve } from "node:path";

const demoDir = resolve(import.meta.dirname, "..");
const sdkDir = resolve(demoDir, "../../tooling/provekit-js");
const output = execFileSync("npm", ["pack", "--json", "--ignore-scripts"], {
  cwd: sdkDir,
  encoding: "utf8",
});
const [{ filename }] = JSON.parse(output);
const tarball = resolve(sdkDir, filename);

try {
  execFileSync(
    "npm",
    ["install", "--no-save", "--legacy-peer-deps", tarball],
    { cwd: demoDir, stdio: "inherit" },
  );
} finally {
  rmSync(tarball, { force: true });
}
