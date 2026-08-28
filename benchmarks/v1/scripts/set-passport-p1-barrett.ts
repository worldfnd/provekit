#!/usr/bin/env bun

function readArray(toml: string, name: string): number[] {
  const match = toml.match(new RegExp(`^${name} = (\\[[^\\n]+\\])$`, "m"));
  if (!match) throw new Error(`missing ${name}`);
  return JSON.parse(match[1]) as number[];
}

function bytesToBigInt(bytes: number[]) {
  return bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

function bigIntToBytes(value: bigint, length: number) {
  const bytes = Array<number>(length).fill(0);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error("Barrett parameter does not fit");
  return bytes;
}

export function setPassportP1Barrett(toml: string, overflowBits: bigint) {
  const rawDsc = readArray(toml, "raw_dsc");
  const offsetMatch = toml.match(/^dsc_pubkey_offset = (\d+)$/m);
  if (!offsetMatch) throw new Error("missing dsc_pubkey_offset");
  const modulusBytes = rawDsc.slice(Number(offsetMatch[1]), Number(offsetMatch[1]) + 512);
  if (modulusBytes.length !== 512) throw new Error("invalid DSC modulus slice");
  const modulus = bytesToBigInt(modulusBytes);
  const modulusBits = BigInt(modulus.toString(2).length);
  const parameter = (1n << (2n * modulusBits + overflowBits)) / modulus;
  return toml.replace(
    /^dsc_barrett_mu = \[[^\n]+\]$/m,
    `dsc_barrett_mu = ${JSON.stringify(bigIntToBytes(parameter, modulusBytes.length + 1))}`,
  );
}

if (import.meta.main) {
  const path = Bun.argv[2];
  const bits = BigInt(Bun.argv[3] ?? "4");
  if (!path) throw new Error("usage: set-passport-p1-barrett.ts <Prover.toml> [overflow-bits]");
  const result = setPassportP1Barrett(await Bun.file(path).text(), bits);
  await Bun.write(path, result);
}
