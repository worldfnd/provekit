#!/usr/bin/env bun

function usage(): never {
  console.error("usage: bun merge-attempts.ts <output.json> <attempts.json>...");
  process.exit(2);
}

if (import.meta.main) {
  const [outputPath, ...inputPaths] = process.argv.slice(2);
  if (!outputPath || inputPaths.length === 0) usage();
  const records: unknown[] = [];
  for (const inputPath of inputPaths) {
    const value = await Bun.file(inputPath).json();
    if (!Array.isArray(value)) throw new Error(`${inputPath} is not a JSON attempt array`);
    records.push(...value);
  }
  await Bun.write(outputPath, `${JSON.stringify(records, null, 2)}\n`);
  console.log(`merged ${records.length} attempt records into ${outputPath}`);
}
