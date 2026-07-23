import * as TOML from "@iarna/toml";

function normalize(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
        key,
        normalize(entry),
      ]),
    );
  }
  return value;
}

export async function loadNoirInputs(url: URL): Promise<Record<string, unknown>> {
  if (url.pathname.endsWith(".json")) {
    return (await Bun.file(url).json()) as Record<string, unknown>;
  }
  if (!url.pathname.endsWith(".toml")) {
    throw new Error(`unsupported Noir input format: ${url.pathname}`);
  }

  const parsed = TOML.parse(await Bun.file(url).text());
  return normalize(parsed) as Record<string, unknown>;
}
