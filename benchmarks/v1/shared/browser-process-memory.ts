interface ProcessRow {
  pid: number;
  ppid: number;
  rss_kib: number;
  command: string;
}

export interface RendererMemorySample {
  at_ms: number;
  renderer_pid: number;
  renderer_rss_kib: number;
}

export interface RendererMemoryReport {
  metric: "peak_chrome_renderer_rss";
  peak_rss_kib: number | null;
  peak_renderer_pid: number | null;
  polling_interval_ms: number;
  sample_count: number;
}

async function processRows(): Promise<ProcessRow[]> {
  const child = Bun.spawn(["ps", "-axo", "pid=,ppid=,rss=,command="], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    child.exited,
  ]);
  if (exitCode !== 0) return [];
  return stdout.split("\n").flatMap((line) => {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/);
    if (!match) return [];
    return [{
      pid: Number.parseInt(match[1]!, 10),
      ppid: Number.parseInt(match[2]!, 10),
      rss_kib: Number.parseInt(match[3]!, 10),
      command: match[4]!,
    }];
  });
}

async function rendererSnapshot(profile: string): Promise<RendererMemorySample | null> {
  const rows = await processRows();
  const root = rows.find(
    (row) =>
      row.command.includes(profile) &&
      row.command.includes("Google Chrome") &&
      !row.command.includes("--type="),
  );
  if (!root) return null;
  const descendants = new Set([root.pid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const row of rows) {
      if (descendants.has(row.ppid) && !descendants.has(row.pid)) {
        descendants.add(row.pid);
        changed = true;
      }
    }
  }
  const renderer = rows
    .filter((row) => descendants.has(row.pid) && row.command.includes("--type=renderer"))
    .sort((left, right) => right.rss_kib - left.rss_kib)[0];
  return renderer
    ? {
        at_ms: Date.now(),
        renderer_pid: renderer.pid,
        renderer_rss_kib: renderer.rss_kib,
      }
    : null;
}

export function startRendererRssSampler(profile: string, pollingIntervalMs = 100) {
  let sampling = true;
  const samples: RendererMemorySample[] = [];
  const completed = (async () => {
    while (sampling) {
      const sample = await rendererSnapshot(profile);
      if (sample) samples.push(sample);
      await Bun.sleep(pollingIntervalMs);
    }
  })();

  return {
    async stop(): Promise<RendererMemoryReport> {
      sampling = false;
      await completed;
      const peak = samples.reduce<RendererMemorySample | undefined>(
        (current, sample) =>
          !current || sample.renderer_rss_kib > current.renderer_rss_kib
            ? sample
            : current,
        undefined,
      );
      return {
        metric: "peak_chrome_renderer_rss",
        peak_rss_kib: peak?.renderer_rss_kib ?? null,
        peak_renderer_pid: peak?.renderer_pid ?? null,
        polling_interval_ms: pollingIntervalMs,
        sample_count: samples.length,
      };
    },
  };
}
