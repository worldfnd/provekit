import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const selfRoot = resolve(
  process.env.SELF_SOURCE_ROOT ??
    join(import.meta.dir, "../../../target/v1-benchmarks/sources/self"),
);
const outputRoot = resolve(
  process.env.SELF_FIXTURE_OUTPUT_ROOT ??
    join(import.meta.dir, "fixtures/self"),
);
const mode = process.env.SELF_FIXTURE_MODE ?? "write";
const sourceRevision = process.env.SELF_SOURCE_REVISION;

if (mode !== "write" && mode !== "check") {
  throw new Error(`SELF_FIXTURE_MODE must be "write" or "check", got "${mode}"`);
}
if (!sourceRevision) {
  throw new Error("SELF_SOURCE_REVISION is required");
}

const asModuleUrl = (path: string) => pathToFileURL(path).href;
const importSource = (path: string) => import(asModuleUrl(join(selfRoot, path)));

const [
  { LeanIMT },
  { SMT },
  { poseidon2 },
  { PassportDocument },
  { createCircuitInputGenerator },
  { genAndInitMockPassportData },
  { hashEndpointWithScope },
  { castFromUUID },
] = await Promise.all([
  importSource("node_modules/@openpassport/zk-kit-lean-imt/dist/index.js"),
  importSource("node_modules/@openpassport/zk-kit-smt/dist/index.js"),
  importSource("node_modules/poseidon-lite/poseidon2.js"),
  importSource("new-common/src/documents/passport/adapter.ts"),
  importSource("new-common/src/circuits/generator.ts"),
  importSource("new-common/src/testing/genMockPassportData.ts"),
  importSource("new-common/src/crypto/scope.ts"),
  importSource("new-common/src/circuits/userId.ts"),
]);

const readJson = async (path: string) =>
  JSON.parse(await Bun.file(join(selfRoot, path)).text());

const [
  serializedDscTree,
  passportNoTree,
  nameAndDobTree,
  nameAndYobTree,
] = await Promise.all([
  readJson("new-common/src/data/serialized_dsc_tree.json"),
  readJson("circuits/tests/consts/ofac/passportNoAndNationalitySMT.json"),
  readJson("circuits/tests/consts/ofac/nameAndDobSMT.json"),
  readJson("circuits/tests/consts/ofac/nameAndYobSMT.json"),
]);

// Self's mock passport helper fills unused data-group hashes with Math.random().
// Pin a small deterministic generator so the passport, signature, commitment,
// and both fixture files are byte-for-byte reproducible.
let randomState = 0x5e1f_2026;
const originalRandom = Math.random;
Math.random = () => {
  randomState = (Math.imul(randomState, 1_664_525) + 1_013_904_223) >>> 0;
  return randomState / 0x1_0000_0000;
};

let passportData;
try {
  passportData = genAndInitMockPassportData(
    "sha256",
    "sha256",
    "rsa_sha256_65537_4096",
    "FRA",
    "000101",
    "300101",
  );
} finally {
  Math.random = originalRandom;
}

const doc = new PassportDocument(passportData);
const generator = createCircuitInputGenerator();
const secret =
  "170141183460469231731687303715884105727";
const scope = hashEndpointWithScope("https://benchmark.self.xyz", "provekit-v1");
const userIdentifier = castFromUUID("00000000-0000-4000-8000-000000000001");

const registerInputs = generator.generateRegisterInputs(
  doc,
  secret,
  serializedDscTree,
  { useTestPadding: true },
);

const commitment = doc.generateCommitment(secret);
const commitmentTree = new LeanIMT(
  (left: bigint, right: bigint) => poseidon2([left, right]),
  [],
);
commitmentTree.insert(BigInt(commitment));

const passportNoSmt = new SMT(poseidon2, true);
passportNoSmt.import(passportNoTree);
const nameAndDobSmt = new SMT(poseidon2, true);
nameAndDobSmt.import(nameAndDobTree);
const nameAndYobSmt = new SMT(poseidon2, true);
nameAndYobSmt.import(nameAndYobTree);

const discloseInputs = generator.generateDiscloseInputs(doc, secret, {
  scope,
  fieldsToReveal: [
    "issuing_state",
    "name",
    "id_number",
    "nationality",
    "date_of_birth",
    "gender",
    "expiry_date",
    "older_than",
    "ofac",
  ],
  merkletree: commitmentTree,
  majority: "18",
  passportNo_smt: passportNoSmt,
  nameAndDob_smt: nameAndDobSmt,
  nameAndYob_smt: nameAndYobSmt,
  forbidden_countries_list: ["ALG", "DZA"],
  user_identifier: userIdentifier,
});

// Input generation normally uses wall-clock time. Freeze the campaign date so
// regeneration does not change the fixture and the age/expiry checks stay valid.
discloseInputs.current_date = ["2", "6", "0", "7", "2", "3"];

const stableJson = (value: Record<string, unknown>) =>
  `${JSON.stringify(
    Object.fromEntries(
      Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
    ),
    null,
    2,
  )}\n`;

const artifacts = [
  {
    name: "self_passport_registration",
    file: "register_sha256_sha256_sha256_rsa_65537_4096.json",
    contents: stableJson(registerInputs),
  },
  {
    name: "self_passport_disclosure",
    file: "vc_and_disclose.json",
    contents: stableJson(discloseInputs),
  },
];

const sha256 = (contents: string) => {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(contents);
  return hasher.digest("hex");
};

const manifest = {
  schema_version: 1,
  source: {
    repository: "https://github.com/selfxyz/self.git",
    revision: sourceRevision,
  },
  fixture: {
    random_seed: "0x5e1f2026",
    secret,
    user_uuid: "00000000-0000-4000-8000-000000000001",
    endpoint: "https://benchmark.self.xyz",
    scope: "provekit-v1",
    current_date_yymmdd: "260723",
    passport: {
      dg_hash: "sha256",
      econtent_hash: "sha256",
      signature: "rsa_sha256_65537_4096",
      nationality: "FRA",
      birth_date_yymmdd: "000101",
      expiry_date_yymmdd: "300101",
    },
    commitment,
  },
  artifacts: artifacts.map(({ name, file, contents }) => ({
    name,
    file,
    size: new TextEncoder().encode(contents).byteLength,
    sha256: sha256(contents),
  })),
};

const files = [
  ...artifacts.map(({ file, contents }) => ({ file, contents })),
  { file: "manifest.json", contents: stableJson(manifest) },
];

await Bun.$`mkdir -p ${outputRoot}`.quiet();

for (const { file, contents } of files) {
  const destination = join(outputRoot, file);
  if (mode === "check") {
    if (!(await Bun.file(destination).exists())) {
      throw new Error(`missing frozen Self fixture: ${destination}`);
    }
    const actual = await Bun.file(destination).text();
    if (actual !== contents) {
      throw new Error(`frozen Self fixture differs from regeneration: ${destination}`);
    }
    console.log(`verified ${destination}`);
  } else {
    await Bun.write(destination, contents);
    console.log(`wrote ${destination}`);
  }
}
