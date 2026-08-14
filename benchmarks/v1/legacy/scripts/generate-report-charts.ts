import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

type Datum = {
  label: string;
  value: number;
  backend?: string;
  environment?: string;
  device?: string;
};

type ChartData = {
  iphone_se_proving_seconds: Record<string, Datum[]>;
  iphone_se_process_peak_bytes: Datum[];
  provekit_wasm_seconds: Record<string, Datum[]>;
  provekit_android_prepare_seconds: Datum[];
  provekit_android_release_seconds: Record<string, Datum[]>;
  provekit_android_cached_recovery_proving_seconds: Record<string, Datum[]>;
  barretenberg_android_proving_seconds: Record<string, Datum[]>;
  arkworks_android_proving_seconds: Record<string, Datum[]>;
  mac_noir_proving_seconds: Record<string, Datum[]>;
  mac_circom_proving_seconds: Record<string, Datum[]>;
  artifact_sizes: Record<string, Datum[]>;
};

type BarretenbergIosSummary = {
  results: Array<{
    workload: "passport" | "webauthn" | "oprf";
    phase: "prove" | "verify" | "e2e";
    median_ns: number;
    process_peak_memory_kb: number;
  }>;
};

const scriptDirectory = dirname(new URL(import.meta.url).pathname);
const benchmarkRoot = resolve(scriptDirectory, "..");
const resultRoot = resolve(benchmarkRoot, "results/run-30041758043");
const chartRoot = resolve(resultRoot, "charts");
const data = (await Bun.file(
  resolve(resultRoot, "report-chart-data.json"),
).json()) as ChartData;
const barretenbergIos = (await Bun.file(
  resolve(resultRoot, "barretenberg-mobile-release/ios-v3-summary.json"),
).json()) as BarretenbergIosSummary;

for (const result of barretenbergIos.results.filter(
  (candidate) => candidate.phase === "prove",
)) {
  const provingLabel =
    result.workload === "oprf"
      ? "Barretenberg 0.87 · native · Taceo"
      : "Barretenberg 0.87 · native";
  data.iphone_se_proving_seconds[result.workload] = [
    ...data.iphone_se_proving_seconds[result.workload].filter(
      (datum) => datum.label !== provingLabel,
    ),
    {
      label: provingLabel,
      value: result.median_ns / 1_000_000_000,
      backend: "barretenberg",
    },
  ];
  const memoryLabel = `${
    result.workload === "passport"
      ? "Passport"
      : result.workload === "webauthn"
        ? "WebAuthn"
        : "OPRF"
  } · Barretenberg native${result.workload === "oprf" ? " · Taceo" : ""}`;
  data.iphone_se_process_peak_bytes = [
    ...data.iphone_se_process_peak_bytes.filter(
      (datum) => datum.label !== memoryLabel,
    ),
    {
      label: memoryLabel,
      value: result.process_peak_memory_kb * 1_000,
      backend: "barretenberg",
    },
  ];
}
await Bun.write(
  resolve(resultRoot, "report-chart-data.json"),
  `${JSON.stringify(data, null, 2)}\n`,
);

await mkdir(chartRoot, { recursive: true });

const palette: Record<string, string> = {
  provekit: "#2563EB",
  barretenberg: "#D97706",
  arkworks: "#6D8B3D",
  rapidsnark: "#C2416C",
  macos: "#334155",
  windows: "#2563EB",
  ios: "#D97706",
  android: "#6D8B3D",
  s24: "#2563EB",
  pixel7: "#D97706",
  m32: "#6D8B3D",
};

function escapeXml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let index = 0;
  while (value >= 1_000 && index < units.length - 1) {
    value /= 1_000;
    index += 1;
  }
  if (index === 0) return `${Math.round(value)} B`;
  const decimals = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(decimals)} ${units[index]}`;
}

function formatValue(value: number, unit: "s" | "bytes"): string {
  if (unit === "s") {
    return value >= 10 ? `${value.toFixed(1)} s` : `${value.toFixed(3)} s`;
  }
  return formatBytes(value);
}

function colorFor(datum: Datum): string {
  const key = datum.backend ?? datum.environment ?? datum.device ?? "provekit";
  return palette[key] ?? "#2563EB";
}

function header(width: number, title: string, subtitle: string): string {
  return `
    <rect width="${width}" height="100%" fill="#FFFFFF"/>
    <text x="56" y="58" class="title">${escapeXml(title)}</text>
    <text x="56" y="88" class="subtitle">${escapeXml(subtitle)}</text>
  `;
}

function panel(
  title: string,
  rows: Datum[],
  y: number,
  options: {
    width: number;
    labelWidth?: number;
    plotWidth?: number;
    unit: "s" | "bytes";
    max?: number;
  },
): { svg: string; height: number } {
  const labelWidth = options.labelWidth ?? 370;
  const plotWidth = options.plotWidth ?? options.width - labelWidth - 210;
  const plotX = 56 + labelWidth;
  const barHeight = 26;
  const rowGap = 17;
  const rowStep = barHeight + rowGap;
  const max = options.max ?? Math.max(...rows.map((row) => row.value)) * 1.08;
  const panelHeight = 60 + rows.length * rowStep;
  const lines: string[] = [];

  lines.push(
    `<text x="56" y="${y + 24}" class="panel-title">${escapeXml(title)}</text>`,
  );
  for (let tick = 0; tick <= 4; tick += 1) {
    const x = plotX + (plotWidth * tick) / 4;
    const value = (max * tick) / 4;
    lines.push(
      `<line x1="${x}" y1="${y + 42}" x2="${x}" y2="${y + panelHeight - 8}" class="grid"/>`,
      `<text x="${x}" y="${y + 38}" text-anchor="middle" class="tick">${formatValue(value, options.unit)}</text>`,
    );
  }

  rows.forEach((row, index) => {
    const rowY = y + 54 + index * rowStep;
    const width = (row.value / max) * plotWidth;
    lines.push(
      `<text x="${plotX - 16}" y="${rowY + 19}" text-anchor="end" class="label">${escapeXml(row.label)}</text>`,
      `<rect x="${plotX}" y="${rowY}" width="${Math.max(width, 2)}" height="${barHeight}" rx="3" fill="${colorFor(row)}"/>`,
      `<text x="${plotX + width + 10}" y="${rowY + 19}" class="value">${formatValue(row.value, options.unit)}</text>`,
    );
  });

  return { svg: lines.join("\n"), height: panelHeight };
}

function document(
  width: number,
  height: number,
  body: string,
  footer: string,
): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img">
  <style>
    text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; fill: #172033; }
    .title { font-size: 28px; font-weight: 700; }
    .subtitle { font-size: 16px; fill: #64748B; }
    .panel-title { font-size: 19px; font-weight: 700; }
    .label { font-size: 15px; }
    .value { font-size: 14px; font-weight: 650; font-variant-numeric: tabular-nums; }
    .tick { font-size: 12px; fill: #64748B; font-variant-numeric: tabular-nums; }
    .grid { stroke: #E2E8F0; stroke-width: 1; }
    .footer { font-size: 13px; fill: #64748B; }
  </style>
  ${body}
  <text x="56" y="${height - 30}" class="footer">${escapeXml(footer)}</text>
</svg>`;
}

async function writeSmallMultiples(
  filename: string,
  title: string,
  subtitle: string,
  sections: Array<{ title: string; rows: Datum[]; unit?: "s" | "bytes" }>,
  unit: "s" | "bytes",
  footer: string,
  width = 1400,
): Promise<void> {
  let y = 116;
  const pieces = [header(width, title, subtitle)];
  for (const section of sections) {
    const rendered = panel(section.title, section.rows, y, {
      width,
      unit: section.unit ?? unit,
    });
    pieces.push(rendered.svg);
    y += rendered.height + 28;
  }
  const height = y + 58;
  await Bun.write(
    resolve(chartRoot, filename),
    document(width, height, pieces.join("\n"), footer),
  );
}

await writeSmallMultiples(
  "iphone-se-proving-time.svg",
  "Proving time on iPhone SE 2022",
  "Median of five measured samples after one warmup; native and Safari WASM remain separate execution surfaces",
  [
    {
      title: "Passport · complete age check",
      rows: data.iphone_se_proving_seconds.passport,
    },
    {
      title: "WebAuthn · assertion ownership",
      rows: data.iphone_se_proving_seconds.webauthn,
    },
    {
      title: "OPRF · Taceo Noir and World ID Circom statements",
      rows: data.iphone_se_proving_seconds.oprf,
    },
  ],
  "s",
  "World ID Arkworks query/nullifier and Taceo Noir OPRF are different statements; compare only within a labeled statement.",
);

await writeSmallMultiples(
  "iphone-se-process-peak-memory.svg",
  "Maximum process peak on iPhone SE 2022",
  "Mobench benchmark-app process high-water mark during proof-only native functions",
  [
    {
      title: "Native proof functions with retained process memory",
      rows: data.iphone_se_process_peak_bytes,
    },
  ],
  "bytes",
  "Browser/WASM process RSS is unavailable and is intentionally excluded.",
);

await writeSmallMultiples(
  "mac-noir-proving-time.svg",
  "Noir proving time on Apple M4 Max",
  "Native CLIs and Chrome single-thread WASM; median of five measured samples after one warmup",
  [
    {
      title: "Passport · complete age check",
      rows: data.mac_noir_proving_seconds.passport,
    },
    {
      title: "WebAuthn · assertion ownership",
      rows: data.mac_noir_proving_seconds.webauthn,
    },
    {
      title: "OPRF · Taceo Noir example",
      rows: data.mac_noir_proving_seconds.oprf,
    },
  ],
  "s",
  "Native and Chrome WASM are distinct execution surfaces; compare backends only within the same workload and surface.",
);

await writeSmallMultiples(
  "mac-circom-proving-time.svg",
  "Circom proving time on Apple M4 Max",
  "Native proof-only functions; median of five measured samples after one warmup",
  [
    {
      title: "Self passport flow · two separate proofs",
      rows: data.mac_circom_proving_seconds.passport,
    },
    {
      title: "WebAuthn · labelled Circom assertion",
      rows: data.mac_circom_proving_seconds.webauthn,
    },
    {
      title: "World ID OPRF flow · two separate proofs",
      rows: data.mac_circom_proving_seconds.oprf,
    },
  ],
  "s",
  "Each Circom lane remains separately labelled where its statement differs from the corresponding Noir workload.",
);

await writeSmallMultiples(
  "provekit-wasm-proving-time.svg",
  "ProveKit V1 proving time across browser environments",
  "Portable single-thread WASM; median of five measured samples after one warmup",
  [
    {
      title: "Passport · complete age check",
      rows: data.provekit_wasm_seconds.passport,
    },
    {
      title: "WebAuthn · assertion ownership",
      rows: data.provekit_wasm_seconds.webauthn,
    },
    {
      title: "OPRF · Taceo Noir example",
      rows: data.provekit_wasm_seconds.oprf,
    },
  ],
  "s",
  "Real-mobile Safari and Chrome rows use BrowserStack Automate; desktop rows use the same single-thread bundle.",
);

await writeSmallMultiples(
  "provekit-android-passport-prepare-time.svg",
  "ProveKit V1 passport preparation time on Android",
  "Native Mobench function; median of five measured samples after one warmup",
  [
    {
      title: "Passport complete age check · preparation",
      rows: data.provekit_android_prepare_seconds,
    },
  ],
  "s",
  "Original APK/Espresso recovery rows; the later release-AAB/Appium matrix is charted separately.",
);

await writeSmallMultiples(
  "provekit-android-release-matrix-time.svg",
  "ProveKit V1 native Android phase timings",
  "Pixel 7 / Android 13; exact-source signed release AABs; median of five measured samples after one warmup",
  [
    {
      title: "Passport · complete age check",
      rows: data.provekit_android_release_seconds.passport,
    },
    {
      title: "WebAuthn · assertion ownership",
      rows: data.provekit_android_release_seconds.webauthn,
    },
    {
      title: "OPRF · Taceo Noir example",
      rows: data.provekit_android_release_seconds.oprf,
    },
  ],
  "s",
  "BrowserStack App Automate + Appium/UiAutomator2; platform-default Rayon pool; one function per session.",
);

await writeSmallMultiples(
  "provekit-android-cached-recovery-proving-time.svg",
  "Supporting ProveKit V1 Android proof recovery",
  "Cached BrowserStack executables; three independent runs aggregate 3 warmups and 6 measured samples",
  [
    {
      title: "Passport · complete age check proof",
      rows: data.provekit_android_cached_recovery_proving_seconds.passport,
    },
    {
      title: "OPRF · Taceo Noir example proof",
      rows: data.provekit_android_cached_recovery_proving_seconds.oprf,
    },
  ],
  "s",
  "Supporting evidence only: BrowserStack retained no downloadable APK or source SHA; not the primary 1 + 5 campaign contract.",
);

await writeSmallMultiples(
  "barretenberg-android-proving-time.svg",
  "Barretenberg 0.87.0 proving time on Android Chrome",
  "Single-thread WASM; median of five measured samples after one warmup",
  [
    {
      title: "Passport · complete age check",
      rows: data.barretenberg_android_proving_seconds.passport,
    },
    {
      title: "WebAuthn · assertion ownership",
      rows: data.barretenberg_android_proving_seconds.webauthn,
    },
    {
      title: "OPRF · Taceo Noir example",
      rows: data.barretenberg_android_proving_seconds.oprf,
    },
  ],
  "s",
  "All 36 workload/phase/device cells passed; this chart shows proof generation only.",
);

await writeSmallMultiples(
  "arkworks-android-oprf-proving-time.svg",
  "Arkworks World ID OPRF proving time on Android",
  "Native Mobench functions; median of five measured samples after one warmup",
  [
    {
      title: "World ID OPRF query circuit",
      rows: data.arkworks_android_proving_seconds.query,
    },
    {
      title: "World ID OPRF nullifier circuit",
      rows: data.arkworks_android_proving_seconds.nullifier,
    },
  ],
  "s",
  "Query and nullifier are separate proofs and are not equivalent to the Taceo Noir OPRF example.",
);

await writeSmallMultiples(
  "artifact-and-proof-sizes.svg",
  "Prover bundle and proof sizes",
  "Exact retained bytes shown in decimal B/KB/MB/GB; panels use independent zero-based scales",
  [
    {
      title: "Prover artifacts and complete browser bundles under 30 MB",
      rows: data.artifact_sizes.prover_bundle_bytes_under_30mb,
    },
    {
      title: "Self passport Groth16 proving keys",
      rows: data.artifact_sizes.self_zkey_bytes,
    },
    {
      title: "Retained proof encodings",
      rows: data.artifact_sizes.proof_size_bytes,
      unit: "bytes",
    },
  ],
  "bytes",
  "* Barretenberg is a shared all-workload static bundle and excludes the separately fetched CRS.",
  1600,
);

console.log(`Generated report charts under ${chartRoot}`);
