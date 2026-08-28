import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "../../../..");
const canonicalPath = resolve(repoRoot, "benchmarks/v1/noir/passport_p1/canonical-record.json");
const circomInputPath = resolve(repoRoot, "benchmarks/v1/circom/fixtures/passport_p1/input.json");
const outputPath = resolve(import.meta.dir, "Prover.toml");

const canonical = await Bun.file(canonicalPath).json() as {
  registration_fixture: { sha256: string };
  public_statement: { current_date_yymmdd: string; minimum_age: string };
};
const source = await Bun.file(circomInputPath).json() as Record<string, string[]>;

const sha256 = (input: string) => new Bun.CryptoHasher("sha256").update(input).digest("hex");
const contents = await Bun.file(resolve(repoRoot, "benchmarks/v1/circom/fixtures/self/register_sha256_sha256_sha256_rsa_65537_4096.json")).text();
if (sha256(contents) !== canonical.registration_fixture.sha256) {
  throw new Error("P1 source registration fixture hash drifted from canonical-record.json");
}

const numbers = (key: string) => source[key].map((value) => BigInt(value));
const bytes = (key: string) => numbers(key).map((value) => {
  if (value < 0n || value > 255n) throw new Error(`${key} contains a non-byte value`);
  return Number(value);
});
const scalar = (key: string) => {
  const values = numbers(key);
  if (values.length !== 1) throw new Error(`${key} must be scalar`);
  return values[0];
};
const int = (key: string) => Number(scalar(key));
const toTomlArray = (value: readonly (string | number | bigint)[]) => `[${value.join(", ")}]`;
const toTomlFieldArray = (value: readonly bigint[]) => `[${value.map((entry) => `"${entry}"`).join(", ")}]`;
const wordsToBigEndianBytes = (words: bigint[], byteLength: number) => {
  let value = 0n;
  for (let i = 0; i < words.length; i += 1) value |= words[i] << BigInt(120 * i);
  const hex = value.toString(16).padStart(byteLength * 2, "0");
  if (hex.length !== byteLength * 2) throw new Error("Self RSA word array does not fit its declared byte length");
  return [...Buffer.from(hex, "hex")];
};

const dscOffset = int("dsc_pubKey_offset");
const rawDsc = bytes("raw_dsc");
const dscKey = rawDsc.slice(dscOffset, dscOffset + 512);
const selfDscKey = wordsToBigEndianBytes(numbers("pubKey_dsc"), 512);
if (Buffer.compare(Buffer.from(dscKey), Buffer.from(selfDscKey)) !== 0) {
  throw new Error("Self pubKey_dsc words do not match the DSC modulus extracted from raw_dsc");
}
const modulus = BigInt(`0x${Buffer.from(dscKey).toString("hex")}`);
const barrettMu = (1n << 8198n) / modulus; // floor(2^(2*4096 + 6) / n), Noir RSA v0.11.0.
const barrettHex = barrettMu.toString(16).padStart(1026, "0");
const barrettBytes = [...Buffer.from(barrettHex, "hex")];
if (barrettBytes.length !== 513) throw new Error("P1 Barrett parameter is not 513 bytes");

const currentDate = [...canonical.public_statement.current_date_yymmdd].map(Number);
const minAgeAscii = [...canonical.public_statement.minimum_age].map((digit) => digit.charCodeAt(0));
const path = numbers("path");
if (path.some((bit) => bit !== 0n && bit !== 1n)) throw new Error("P1 path is not binary");

const toml = [
  "# Generated from the P1 canonical record; do not edit by hand.",
  `raw_dsc = ${toTomlArray(rawDsc)}`,
  `raw_dsc_actual_length = ${int("raw_dsc_actual_length")}`,
  `dsc_pubkey_offset = ${dscOffset}`,
  `dsc_pubkey_actual_size = ${int("dsc_pubKey_actual_size")}`,
  `dg1 = ${toTomlArray(bytes("dg1"))}`,
  `dg1_hash_offset = ${int("dg1_hash_offset")}`,
  `econtent = ${toTomlArray(bytes("eContent"))}`,
  `econtent_padded_length = ${int("eContent_padded_length")}`,
  `signed_attr = ${toTomlArray(bytes("signed_attr"))}`,
  `signed_attr_padded_length = ${int("signed_attr_padded_length")}`,
  `signed_attr_econtent_hash_offset = ${int("signed_attr_econtent_hash_offset")}`,
  `signature_passport = ${toTomlArray(wordsToBigEndianBytes(numbers("signature_passport"), 512))}`,
  `dsc_barrett_mu = ${toTomlArray(barrettBytes)}`,
  `merkle_root = "${scalar("merkle_root")}"`,
  `leaf_depth = ${int("leaf_depth")}`,
  `path = ${toTomlArray(path)}`,
  `siblings = ${toTomlFieldArray(numbers("siblings"))}`,
  `csca_tree_leaf = "${scalar("csca_tree_leaf")}"`,
  `current_date = ${toTomlArray(currentDate)}`,
  `minimum_age = ${toTomlArray(minAgeAscii)}`,
  "",
].join("\n");

await Bun.write(outputPath, toml);
console.log(`wrote ${outputPath}`);
