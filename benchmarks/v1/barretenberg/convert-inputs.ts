import { loadNoirInputs } from "./load-inputs";

const input = Bun.argv[2];
const output = Bun.argv[3];
if (!input || !output) {
  throw new Error("usage: bun run inputs -- <Prover.toml|inputs.json> <output.json>");
}

const inputs = await loadNoirInputs(new URL(input, `file://${process.cwd()}/`));
await Bun.write(output, `${JSON.stringify(inputs, null, 2)}\n`);
console.log(`Wrote ${output}`);
