import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "../../..");
const sourceRoot =
  process.env.WORLD_ID_PROTOCOL_ROOT ??
  resolve(repoRoot, "target/v1-benchmarks/sources/world-id-protocol");
const outputRoot =
  process.env.CIRCOM_OPRF_INPUT_ROOT ??
  resolve(repoRoot, "target/v1-benchmarks/circom-browser/oprf");

async function extractFirstWitnessInput(source: string): Promise<unknown> {
  const marker = "calculateWitness(";
  const markerIndex = source.indexOf(marker);
  if (markerIndex === -1) throw new Error("calculateWitness call not found");
  const start = source.indexOf("{", markerIndex + marker.length);
  if (start === -1) throw new Error("witness input object not found");

  let depth = 0;
  let end = -1;
  for (let index = start; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        end = index + 1;
        break;
      }
    }
  }
  if (end === -1) throw new Error("unterminated witness input object");

  // The source is an immutable, hash-pinned repository fixture. Evaluating only
  // the extracted object preserves its BigInt values without lossy parsing.
  return Function(`"use strict"; return (${source.slice(start, end)});`)();
}

async function writeInput(testName: string, outputName: string) {
  const sourcePath = resolve(sourceRoot, "circom/tests/tests", testName);
  const source = await Bun.file(sourcePath).text();
  const input = await extractFirstWitnessInput(source);
  const json = JSON.stringify(
    input,
    (_, value) => (typeof value === "bigint" ? value.toString() : value),
    2,
  );
  await Bun.write(resolve(outputRoot, outputName), `${json}\n`);
}

await mkdir(outputRoot, { recursive: true });
await Promise.all([
  writeInput("oprf_query.test.js", "oprf_query.input.json"),
  writeInput("oprf_nullifier.test.js", "oprf_nullifier.input.json"),
]);

console.log(`Extracted frozen World ID OPRF inputs into ${outputRoot}`);
