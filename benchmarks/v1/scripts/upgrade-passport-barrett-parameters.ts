#!/usr/bin/env bun

const OVERFLOW_BITS = 6n;

export function bytesToBigInt(bytes: number[]): bigint {
  return bytes.reduce((value, byte) => {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`invalid byte ${byte}`);
    }
    return (value << 8n) | BigInt(byte);
  }, 0n);
}

export function bigIntToBytes(value: bigint, length: number): number[] {
  if (value < 0n) throw new Error("cannot encode a negative integer");
  const bytes = Array<number>(length).fill(0);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) {
    throw new Error(`integer does not fit in ${length} bytes`);
  }
  return bytes;
}

export function barrettParameter(modulusBytes: number[]): number[] {
  const modulus = bytesToBigInt(modulusBytes);
  if (modulus === 0n) throw new Error("modulus must be non-zero");
  const modulusBits = BigInt(modulus.toString(2).length);
  const parameter = (1n << (2n * modulusBits + OVERFLOW_BITS)) / modulus;
  return bigIntToBytes(parameter, modulusBytes.length + 1);
}

function readArray(toml: string, name: string): number[] {
  const match = toml.match(new RegExp(`^${name} = (\\[[^\\n]+\\])$`, "m"));
  if (!match) throw new Error(`missing ${name}`);
  const value = JSON.parse(match[1]) as unknown;
  if (!Array.isArray(value)) throw new Error(`${name} is not an array`);
  return value as number[];
}

export function upgradePassportBarrettParameters(toml: string): string {
  const pairs = [
    ["dsc_pubkey", "dsc_barrett_mu"],
    ["csc_pubkey", "csc_barrett_mu"],
  ] as const;

  let result = toml;
  for (const [modulusName, parameterName] of pairs) {
    const modulus = readArray(result, modulusName);
    const parameter = barrettParameter(modulus);
    const parameterLine = `${parameterName} = ${JSON.stringify(parameter)}`;
    const pattern = new RegExp(`^${parameterName} = \\[[^\\n]+\\]$`, "m");
    if (!pattern.test(result)) throw new Error(`missing ${parameterName}`);
    result = result.replace(pattern, parameterLine);
  }
  return result;
}

if (import.meta.main) {
  const input = Bun.argv[2];
  if (!input) {
    throw new Error("usage: upgrade-passport-barrett-parameters.ts <Prover.toml>");
  }
  const original = await Bun.file(input).text();
  const upgraded = upgradePassportBarrettParameters(original);
  if (upgraded !== original) await Bun.write(input, upgraded);
  console.log(`Validated six-overflow-bit Passport Barrett parameters in ${input}`);
}
