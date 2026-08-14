import { resolve } from "node:path";
import { CSV_COLUMNS } from "./schema";

type Row = Record<(typeof CSV_COLUMNS)[number], string>;

const here = import.meta.dir;
const canonicalPath = resolve(
  process.env.INPUT_TO_PROOF_CANONICAL_CSV ?? resolve(here, "input-to-proof-samples.csv"),
);
const replacementPath = resolve(
  process.env.INPUT_TO_PROOF_FIXED16_CSV ??
    resolve(here, "../legacy/wasm/wasm-multithread-16-samples.csv"),
);
const outputPath = resolve(
  process.env.INPUT_TO_PROOF_MERGED_OUTPUT_CSV ?? canonicalPath,
);

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        value += '"';
        index += 1;
      } else if (character === '"') {
        quoted = false;
      } else {
        value += character;
      }
    } else if (character === '"') {
      quoted = true;
    } else if (character === ",") {
      row.push(value);
      value = "";
    } else if (character === "\n") {
      row.push(value);
      rows.push(row);
      row = [];
      value = "";
    } else if (character !== "\r") {
      value += character;
    }
  }
  assert(!quoted, "CSV contains an unterminated quoted field");
  if (value.length || row.length) {
    row.push(value);
    rows.push(row);
  }
  return rows;
}

function readRows(text: string, label: string): Row[] {
  const parsed = parseCsv(text);
  const header = parsed.shift();
  assert(header?.join("\0") === CSV_COLUMNS.join("\0"), `${label}: schema/order differs from input-to-proof-samples.csv`);
  return parsed.filter((values) => values.length > 1).map((values, rowIndex) => {
    assert(values.length === CSV_COLUMNS.length, `${label}: row ${rowIndex + 2} has ${values.length} fields, expected ${CSV_COLUMNS.length}`);
    return Object.fromEntries(CSV_COLUMNS.map((column, index) => [column, values[index]])) as Row;
  });
}

function csvValue(value: string) {
  return /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

function seriesKey(row: Row) {
  return [row.circuit, row.hardware, row.prover, row.timing_mode].join("|");
}

const canonicalRows = readRows(await Bun.file(canonicalPath).text(), "canonical CSV");
const fixedRows = readRows(await Bun.file(replacementPath).text(), "fixed-16 CSV");
assert(fixedRows.length === 134, `fixed-16 CSV expected 134 rows, found ${fixedRows.length}`);
assert(fixedRows.every((row) => row.hardware === "macbook_m4"), "fixed-16 CSV contains non-Mac rows");

const fixedBySeries = new Map<string, Row[]>();
for (const row of fixedRows) {
  const key = seriesKey(row);
  fixedBySeries.set(key, [...(fixedBySeries.get(key) ?? []), row]);
}
assert(fixedBySeries.size === 24, `fixed-16 CSV expected 24 Mac series, found ${fixedBySeries.size}`);

const canonicalMacSeries = new Set(canonicalRows.filter((row) => row.hardware === "macbook_m4").map(seriesKey));
assert(canonicalMacSeries.size === 24, `canonical CSV expected 24 Mac series, found ${canonicalMacSeries.size}`);

const merged: Row[] = [];
const inserted = new Set<string>();
for (const row of canonicalRows) {
  if (row.hardware !== "macbook_m4") {
    merged.push(row);
    continue;
  }
  const key = seriesKey(row);
  if (inserted.has(key)) continue;
  const replacement = fixedBySeries.get(key);
  assert(replacement, `fixed-16 CSV missing Mac series ${key}`);
  merged.push(...replacement);
  inserted.add(key);
}
assert(inserted.size === fixedBySeries.size, "not all fixed-16 Mac series were inserted");

const attemptIds = new Set<string>();
for (const row of merged) {
  assert(!attemptIds.has(row.attempt_id), `duplicate attempt_id after merge: ${row.attempt_id}`);
  attemptIds.add(row.attempt_id);
}

const csv = [
  CSV_COLUMNS.join(","),
  ...merged.map((row) => CSV_COLUMNS.map((column) => csvValue(row[column])).join(",")),
].join("\n") + "\n";
await Bun.write(outputPath, csv);
console.log(`${outputPath}: ${merged.length} rows; replaced ${inserted.size} Mac series with fixed-16 evidence; retained ${merged.filter((row) => row.hardware !== "macbook_m4").length} mobile rows`);
