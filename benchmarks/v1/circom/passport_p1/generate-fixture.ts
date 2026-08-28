import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "../../../..");
const canonicalPath = resolve(
  process.env.P1_CANONICAL_RECORD ??
    `${repoRoot}/benchmarks/v1/noir/passport_p1/canonical-record.json`,
);
const outputPath = resolve(
  process.env.P1_CIRCOM_FIXTURE ??
    `${repoRoot}/benchmarks/v1/circom/fixtures/passport_p1/input.json`,
);
const manifestPath = resolve(
  process.env.P1_CIRCOM_MANIFEST ??
    `${repoRoot}/benchmarks/v1/circom/fixtures/passport_p1/manifest.json`,
);
const mode = process.env.P1_FIXTURE_MODE ?? "write";

if (mode !== "write" && mode !== "check") {
  throw new Error(`P1_FIXTURE_MODE must be \"write\" or \"check\", got ${mode}`);
}

type CanonicalRecord = {
  self_source_revision: string;
  registration_fixture: { path: string; sha256: string };
  public_statement: {
    current_date_yymmdd: string;
    minimum_age: string;
    fixture_id: string;
  };
};

const canonical = (await Bun.file(canonicalPath).json()) as CanonicalRecord;
const sourcePath = resolve(repoRoot, canonical.registration_fixture.path);
const sourceContents = await Bun.file(sourcePath).text();
const sourceHash = new Bun.CryptoHasher("sha256").update(sourceContents).digest("hex");
if (sourceHash !== canonical.registration_fixture.sha256) {
  throw new Error(
    `canonical registration fixture hash drift: expected ${canonical.registration_fixture.sha256}, got ${sourceHash}`,
  );
}

const source = JSON.parse(sourceContents) as Record<string, string[]>;
const currentDate = [...canonical.public_statement.current_date_yymmdd];
const minimumAge = [...canonical.public_statement.minimum_age];
if (!/^\d{6}$/.test(currentDate.join("")) || !/^\d{2}$/.test(minimumAge.join(""))) {
  throw new Error("P1 canonical date must be YYMMDD and its minimum age must be two decimal digits");
}

const { secret: _secret, ...p1Input } = source;
const input = {
  ...p1Input,
  current_date: currentDate,
  minimum_age: minimumAge.map((digit) => String(digit.charCodeAt(0))),
};

const stableJson = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;
const inputContents = stableJson(input);
const inputHash = new Bun.CryptoHasher("sha256").update(inputContents).digest("hex");
const manifest = {
  schema_version: 1,
  profile: "P1",
  canonical_record: {
    path: "benchmarks/v1/noir/passport_p1/canonical-record.json",
    sha256: new Bun.CryptoHasher("sha256")
      .update(await Bun.file(canonicalPath).text())
      .digest("hex"),
  },
  source: {
    self_revision: canonical.self_source_revision,
    registration_fixture: canonical.registration_fixture,
  },
  public_statement: {
    merkle_root: input.merkle_root,
    current_date_yymmdd: canonical.public_statement.current_date_yymmdd,
    minimum_age: canonical.public_statement.minimum_age,
    fixture_id: canonical.public_statement.fixture_id,
  },
  artifact: {
    file: "input.json",
    sha256: inputHash,
    size: new TextEncoder().encode(inputContents).byteLength,
  },
};

const outputs = [
  { path: outputPath, contents: inputContents },
  { path: manifestPath, contents: stableJson(manifest) },
];
for (const output of outputs) {
  if (mode === "check") {
    if (!(await Bun.file(output.path).exists())) {
      throw new Error(`missing frozen P1 fixture: ${output.path}`);
    }
    if ((await Bun.file(output.path).text()) !== output.contents) {
      throw new Error(`frozen P1 fixture differs from the canonical record: ${output.path}`);
    }
  } else {
    await Bun.write(output.path, output.contents);
  }
  console.log(`${mode === "check" ? "verified" : "wrote"} ${output.path}`);
}
