import { p256 } from "@noble/curves/nist.js";

const TOML_OUTPUT = new URL("./Prover.toml", import.meta.url);
const JSON_OUTPUT = new URL("./inputs.json", import.meta.url);
const ORIGIN = "https://benchmark.provekit.dev";
const RP_ID = "benchmark.provekit.dev";
const CLIENT_DATA_MAX = 256;
const AUTHENTICATOR_DATA_MAX = 64;
const SCALAR_SLICES = 65;
const LIMB_BASE = 1n << 120n;
const LIMB_MASK = LIMB_BASE - 1n;

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

function base64url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function bytesToBigint(value: Uint8Array): bigint {
  let output = 0n;
  for (const byte of value) output = (output << 8n) | BigInt(byte);
  return output;
}

function bigintToBytes(value: bigint): Uint8Array {
  const output = new Uint8Array(32);
  let remaining = value;
  for (let index = output.length - 1; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error("P-256 value does not fit in 32 bytes");
  return output;
}

function limbs(value: bigint): [string, string, string] {
  return [
    String(value & LIMB_MASK),
    String((value >> 120n) & LIMB_MASK),
    String(value >> 240n),
  ];
}

function foldSignedSlices(values: readonly number[]): bigint {
  return values.reduce((accumulator, value) => accumulator * 16n + BigInt(value * 2 - 15), 0n);
}

function scalarWitness(value: bigint) {
  const skew = (value & 1n) === 0n;
  let remaining = value + (skew ? 1n : 0n);
  const littleEndianSlices: number[] = [];

  for (let index = 0; index < SCALAR_SLICES; index += 1) {
    let digit = Number(remaining & 0xfn);
    let next = (remaining - BigInt(digit)) >> 4n;
    if (index < SCALAR_SLICES - 1 && (next & 1n) === 0n) {
      digit -= 16;
      next += 1n;
    }
    const slice = (digit + 15) / 2;
    if (!Number.isInteger(slice) || slice < 0 || slice > 15) {
      throw new Error("failed to encode signed radix-16 scalar");
    }
    littleEndianSlices.push(slice);
    remaining = next;
  }
  if (remaining !== 0n) throw new Error("signed radix-16 scalar overflow");

  const slices = littleEndianSlices.reverse();
  const [lowLimb, midLimb, highLimb] = limbs(value).map(BigInt);
  const high = foldSignedSlices(slices.slice(0, 5));
  const mid = foldSignedSlices(slices.slice(5, 35));
  const low = foldSignedSlices(slices.slice(35));
  const borrowMid = high - highLimb;
  const borrowLow = mid + borrowMid * LIMB_BASE - midLimb;

  if (![borrowLow, borrowMid].every((borrow) => borrow === 0n || borrow === 1n)) {
    throw new Error("signed radix-16 borrow is not boolean");
  }
  if (low + borrowLow * LIMB_BASE !== lowLimb + (skew ? 1n : 0n)) {
    throw new Error("signed radix-16 limbs do not reconstruct the scalar");
  }

  return {
    limbs: limbs(value),
    slices,
    skew,
    borrowLow: borrowLow === 1n,
    borrowMid: borrowMid === 1n,
  };
}

const BIGCURVE_MODULUS_SLICES = [
  8, 1, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 13, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13, 11, 4, 0,
  12, 0, 10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8, 10, 1, 15, 0,
  15, 10, 12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
] as const;

function acceptedByVendoredBigcurve(slices: readonly number[]): boolean {
  for (let index = 0; index < BIGCURVE_MODULUS_SLICES.length; index += 1) {
    if (slices[index] < BIGCURVE_MODULUS_SLICES[index]) return true;
    if (slices[index] > BIGCURVE_MODULUS_SLICES[index]) return false;
  }
  return true;
}

function quoteStrings(values: readonly string[]): string {
  return `[${values.map((value) => JSON.stringify(value)).join(", ")}]`;
}

function numbers(values: Uint8Array | readonly number[]): string {
  return `[${Array.from(values).join(", ")}]`;
}

function pad(values: Uint8Array, length: number): Uint8Array {
  if (values.length > length) throw new Error(`fixture length ${values.length} exceeds ${length}`);
  const output = new Uint8Array(length);
  output.set(values);
  return output;
}

const privateKey = new Uint8Array(32);
privateKey[31] = 1;
const publicKey = p256.getPublicKey(privateKey, false);
const publicKeyX = publicKey.slice(1, 33);
const publicKeyY = publicKey.slice(33);
async function makeCandidate(attempt: number) {
  const challenge = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  challenge[30] = attempt >> 8;
  challenge[31] = attempt & 0xff;
  const clientDataJson = new TextEncoder().encode(
    JSON.stringify({
      type: "webauthn.get",
      challenge: base64url(challenge),
      origin: ORIGIN,
      crossOrigin: false,
    }),
  );
  const rpIdHash = await sha256(new TextEncoder().encode(RP_ID));
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(rpIdHash);
  authenticatorData[32] = 0x05;
  const clientDataHash = await sha256(clientDataJson);
  const signedBytes = concat(authenticatorData, clientDataHash);
  const messageDigest = await sha256(signedBytes);
  const signature = p256.sign(signedBytes, privateKey);
  const r = bytesToBigint(signature.slice(0, 32));
  const s = bytesToBigint(signature.slice(32));
  const message = bytesToBigint(messageDigest);
  const scalarField = p256.Point.Fn;
  const inverseS = scalarField.inv(s);
  const sGValue = scalarField.mul(scalarField.create(message), inverseS);
  const sPValue = scalarField.mul(r, inverseS);
  const sG = scalarWitness(sGValue);
  const sP = scalarWitness(sPValue);
  return {
    attempt,
    authenticatorData,
    challenge,
    clientDataJson,
    message,
    publicKeyX,
    publicKeyY,
    r,
    rpIdHash,
    s,
    sG,
    sGValue,
    signature,
    sP,
    sPValue,
  };
}

let candidate = await makeCandidate(0);
while (
  (!acceptedByVendoredBigcurve(candidate.sG.slices) ||
    !acceptedByVendoredBigcurve(candidate.sP.slices)) &&
  candidate.attempt < 65_535
) {
  candidate = await makeCandidate(candidate.attempt + 1);
}
if (
  !acceptedByVendoredBigcurve(candidate.sG.slices) ||
  !acceptedByVendoredBigcurve(candidate.sP.slices)
) {
  throw new Error("could not find a deterministic assertion accepted by vendored BigCurve");
}

const {
  attempt,
  authenticatorData,
  challenge,
  clientDataJson,
  message,
  r,
  rpIdHash,
  s,
  sG,
  signature,
  sP,
} = candidate;
const clientDataText = new TextDecoder().decode(clientDataJson);
const challengeIndex = clientDataText.indexOf(base64url(challenge));
const originIndex = clientDataText.indexOf(ORIGIN);
if (challengeIndex < 0 || originIndex < 0) throw new Error("fixture fields are absent from clientDataJSON");

const scalarField = p256.Point.Fn;
const inverseS = scalarField.inv(s);
const sGValue = scalarField.mul(scalarField.create(message), inverseS);
const sPValue = scalarField.mul(r, inverseS);
const rPoint = p256.Point.BASE.multiply(sGValue).add(p256.Point.fromAffine({
  x: bytesToBigint(publicKeyX),
  y: bytesToBigint(publicKeyY),
}).multiply(sPValue));
const affineR = rPoint.toAffine();
if (affineR.x !== r) throw new Error("fixture does not satisfy the circuit's direct R.x check");

const rPointY = bigintToBytes(affineR.y);
const lines = [
  "# Generated by generate-fixture.ts. Do not edit by hand.",
  `# Deterministic candidate: ${attempt}.`,
  `challenge = ${numbers(challenge)}`,
  `rp_id_hash = ${numbers(rpIdHash)}`,
  `origin = ${numbers(new TextEncoder().encode(ORIGIN))}`,
  "required_flags = 5",
  `public_key_x = ${numbers(publicKeyX)}`,
  `public_key_y = ${numbers(publicKeyY)}`,
  `signature = ${numbers(signature)}`,
  `challenge_index = ${JSON.stringify(String(challengeIndex))}`,
  `origin_index = ${JSON.stringify(String(originIndex))}`,
  `r_point_y = ${numbers(rPointY)}`,
  `message_limbs = ${quoteStrings(limbs(message))}`,
  `public_key_x_limbs = ${quoteStrings(limbs(bytesToBigint(publicKeyX)))}`,
  `public_key_y_limbs = ${quoteStrings(limbs(bytesToBigint(publicKeyY)))}`,
  `signature_r_limbs = ${quoteStrings(limbs(r))}`,
  `signature_s_limbs = ${quoteStrings(limbs(s))}`,
  `r_point_y_limbs = ${quoteStrings(limbs(affineR.y))}`,
  `s_g_limbs = ${quoteStrings(sG.limbs)}`,
  `s_g_slices = ${numbers(sG.slices)}`,
  `s_g_skew = ${sG.skew}`,
  `s_g_borrow_low = ${sG.borrowLow}`,
  `s_g_borrow_mid = ${sG.borrowMid}`,
  `s_p_limbs = ${quoteStrings(sP.limbs)}`,
  `s_p_slices = ${numbers(sP.slices)}`,
  `s_p_skew = ${sP.skew}`,
  `s_p_borrow_low = ${sP.borrowLow}`,
  `s_p_borrow_mid = ${sP.borrowMid}`,
  "",
  "[client_data_json]",
  `storage = ${numbers(pad(clientDataJson, CLIENT_DATA_MAX))}`,
  `len = ${JSON.stringify(String(clientDataJson.length))}`,
  "",
  "[authenticator_data]",
  `storage = ${numbers(pad(authenticatorData, AUTHENTICATOR_DATA_MAX))}`,
  `len = ${JSON.stringify(String(authenticatorData.length))}`,
  "",
];

const inputs = {
  challenge: Array.from(challenge),
  rp_id_hash: Array.from(rpIdHash),
  origin: Array.from(new TextEncoder().encode(ORIGIN)),
  required_flags: "5",
  public_key_x: Array.from(publicKeyX),
  public_key_y: Array.from(publicKeyY),
  signature: Array.from(signature),
  client_data_json: {
    storage: Array.from(pad(clientDataJson, CLIENT_DATA_MAX)),
    len: String(clientDataJson.length),
  },
  authenticator_data: {
    storage: Array.from(pad(authenticatorData, AUTHENTICATOR_DATA_MAX)),
    len: String(authenticatorData.length),
  },
  challenge_index: String(challengeIndex),
  origin_index: String(originIndex),
  r_point_y: Array.from(rPointY),
  message_limbs: limbs(message),
  public_key_x_limbs: limbs(bytesToBigint(publicKeyX)),
  public_key_y_limbs: limbs(bytesToBigint(publicKeyY)),
  signature_r_limbs: limbs(r),
  signature_s_limbs: limbs(s),
  r_point_y_limbs: limbs(affineR.y),
  s_g_limbs: sG.limbs,
  s_g_slices: sG.slices,
  s_g_skew: sG.skew,
  s_g_borrow_low: sG.borrowLow,
  s_g_borrow_mid: sG.borrowMid,
  s_p_limbs: sP.limbs,
  s_p_slices: sP.slices,
  s_p_skew: sP.skew,
  s_p_borrow_low: sP.borrowLow,
  s_p_borrow_mid: sP.borrowMid,
};

await Promise.all([
  Bun.write(TOML_OUTPUT, lines.join("\n")),
  Bun.write(JSON_OUTPUT, `${JSON.stringify(inputs, null, 2)}\n`),
]);
console.log(`wrote deterministic WebAuthn fixtures to ${TOML_OUTPUT.pathname} and ${JSON_OUTPUT.pathname}`);
