import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const nargo = process.env.P1_NARGO ??
  "../../../../target/v1-benchmarks/tools/nargo-1.0.0-beta.19-aarch64-apple-darwin/nargo";
const canonical = await Bun.file("Prover.toml").text();
const evidence: Array<{ name: string; accepted: boolean; output: string }> = [];

function replaceArrayEntry(input: string, key: string, index: number, next: string): string {
  const pattern = new RegExp(`^${key} = \\[([^\\]]+)\\]$`, "m");
  const match = input.match(pattern);
  if (!match) throw new Error(`missing array ${key}`);
  const values = match[1].split(",").map((value) => value.trim());
  values[index] = next;
  return input.replace(pattern, `${key} = [${values.join(", ")}]`);
}

function arrayEntry(input: string, key: string, index: number): number {
  const pattern = new RegExp(`^${key} = \\[([^\\]]+)\\]$`, "m");
  const match = input.match(pattern);
  if (!match) throw new Error(`missing array ${key}`);
  const value = Number.parseInt(match[1].split(",")[index]?.trim() ?? "", 10);
  if (!Number.isInteger(value)) throw new Error(`missing ${key}[${index}]`);
  return value;
}

function scalar(input: string, key: string): number {
  const match = input.match(new RegExp(`^${key} = (\\d+)$`, "m"));
  if (!match) throw new Error(`missing scalar ${key}`);
  return Number.parseInt(match[1], 10);
}

const dscPubkeyOffset = scalar(canonical, "dsc_pubkey_offset");
const derPrefixMutationIndex = dscPubkeyOffset - 33;
const derPrefixByte = arrayEntry(canonical, "raw_dsc", derPrefixMutationIndex);

const cases = [
  { name: "positive", contents: canonical, expected: true },
  { name: "dg1-byte-mutated", contents: replaceArrayEntry(canonical, "dg1", 0, "98"), expected: false },
  {
    name: "registry-root-mutated",
    contents: canonical.replace(/^merkle_root = "(\d+)"$/m, (_, root) => `merkle_root = "${BigInt(root) + 1n}"`),
    expected: false,
  },
  { name: "current-date-expired", contents: replaceArrayEntry(canonical, "current_date", 0, "9"), expected: false },
  { name: "minimum-age-raised", contents: replaceArrayEntry(canonical, "minimum_age", 0, "57"), expected: false },
  {
    name: "dsc-der-prefix-mutated",
    contents: replaceArrayEntry(canonical, "raw_dsc", derPrefixMutationIndex, String(derPrefixByte ^ 1)),
    expected: false,
  },
];

const root = await mkdtemp(join(tmpdir(), "passport-p1-mutations-"));
for (const testCase of cases) {
  const inputBase = join(root, testCase.name);
  await Bun.write(`${inputBase}.toml`, testCase.contents);
  const child = Bun.spawnSync([nargo, "execute", `p1-${testCase.name}`, "--prover-name", inputBase, "--silence-warnings"], {
    cwd: import.meta.dir,
    stdout: "pipe",
    stderr: "pipe",
  });
  const output = `${new TextDecoder().decode(child.stdout)}${new TextDecoder().decode(child.stderr)}`;
  const accepted = child.exitCode === 0;
  evidence.push({ name: testCase.name, accepted, output });
  if (accepted !== testCase.expected) {
    await Bun.write("target/p1-mutation-evidence.json", JSON.stringify(evidence, null, 2) + "\n");
    throw new Error(`${testCase.name}: expected accepted=${testCase.expected}, got accepted=${accepted}`);
  }
}
await Bun.write("target/p1-mutation-evidence.json", JSON.stringify(evidence, null, 2) + "\n");
console.log("P1 positive and DG1/root/current-date/minimum-age/DER-prefix mutation gates passed");
