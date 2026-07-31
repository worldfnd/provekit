import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "../../..");
const source = resolve(
  repoRoot,
  "target/v1-benchmarks/circom-browser/oprf/oprf_nullifier.input.json",
);
const destination = resolve(repoRoot, "noir-examples/oprf/Prover.toml");

const input = await Bun.file(source).json() as Record<string, any>;
const q = (value: unknown) => JSON.stringify(String(value));
const point = (value: unknown[]) => `{ x = ${q(value[0])}, y = ${q(value[1])} }`;
const points = (values: unknown[][]) => `[
${values.map((value) => `  ${point(value)},`).join("\n")}
]`;
const fields = (values: unknown[]) => `[
${values.map((value) => `  ${q(value)},`).join("\n")}
]`;

const toml = `# Generated from the immutable World ID Protocol Circom fixture.
# Do not edit by hand; run this generator and compare hashes instead.
issuer_schema_id = ${q(input.issuer_schema_id)}
cred_pk = ${point(input.cred_pk)}
current_time_stamp = ${q(input.current_timestamp)}
cred_genesis_issued_at_min = ${q(input.cred_genesis_issued_at_min)}
root = ${q(input.merkle_root)}
depth = ${q(input.depth)}
rp_id = ${q(input.rp_id)}
action = ${q(input.action)}
oprf_pk = ${point(input.oprf_pk)}
nonce = ${q(input.nonce)}
signal_hash = ${q(input.signal_hash)}
id_commitment = ${q(input.id_commitment)}

[inputs]
dlog_e = ${q(input.dlog_e)}
dlog_s = ${q(input.dlog_s)}
oprf_response_blinded = ${point(input.oprf_response_blinded)}
oprf_response = ${point(input.oprf_response)}
id_commitment_r = ${q(input.id_commitment_r)}

[inputs.query_inputs]
user_pk = ${points(input.pk)}
pk_index = ${q(input.pk_index)}
query_s = ${q(input.s)}
query_r = [${input.r.map(q).join(", ")}]
cred_type_id = ${q(input.issuer_schema_id)}
cred_genesis_issued_at = ${q(input.cred_genesis_issued_at)}
cred_expires_at = ${q(input.cred_expires_at)}
cred_user_id_r = ${q(input.cred_user_id_r)}
cred_id = ${q(input.cred_id)}
cred_s = ${q(input.cred_s)}
cred_r = [${input.cred_r.map(q).join(", ")}]
beta = ${q(input.beta)}

[inputs.query_inputs.cred_hashes]
claims_hash = ${q(input.cred_hashes[0])}
associated_data_hash = ${q(input.cred_hashes[1])}

[inputs.query_inputs.merkle_proof]
mt_index = ${q(input.mt_index)}
siblings = ${fields(input.siblings)}
`;

await Bun.write(destination, toml);
console.log(`wrote ${destination} from ${source}`);
