#!/usr/bin/env bun

import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

interface Options {
  output: string;
  campaign: string;
  apk: string;
  warmup: number;
  samples: number;
  timeoutSeconds: number;
  workloads: string[];
  rebootBeforeEach: boolean;
  passportSingleThread: boolean;
  workerProcessSuffix: string;
}

const workloads = [
  ["oprf", "bench_mobile::bench_oprf_prove"],
  ["webauthn", "bench_mobile::bench_webauthn_assertion_prove"],
  ["passport", "bench_mobile::bench_passport_complete_age_check_prove"],
] as const;

export function parseBenchJson(log: string): unknown {
  const chunks = log
    .split(/\r?\n/)
    .filter((line) => line.includes("BENCH_JSON_CHUNK "))
    .map((line) => line.slice(line.indexOf("BENCH_JSON_CHUNK ") + "BENCH_JSON_CHUNK ".length));
  if (chunks.length === 0) throw new Error("logcat contains no BENCH_JSON_CHUNK records");
  return JSON.parse(chunks.join(""));
}

export function parseFailureJson(log: string): unknown | null {
  const line = log
    .split(/\r?\n/)
    .findLast((candidate) => candidate.includes("BENCH_FAILURE_JSON "));
  if (!line) return null;
  return JSON.parse(
    line.slice(line.indexOf("BENCH_FAILURE_JSON ") + "BENCH_FAILURE_JSON ".length),
  );
}

export function orchestrationFailure(
  workload: string,
  functionName: string,
  error: unknown,
  evidencePath: string,
) {
  return {
    workload,
    function: functionName,
    status: "not_run",
    failure: {
      schema_version: 1,
      kind: "device_orchestration_failed",
      message: error instanceof Error ? error.message : String(error),
    },
    evidence_path: evidencePath,
  };
}

function positiveInteger(value: string, flag: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${flag} must be positive`);
  return parsed;
}

function parseArgs(args: string[]): Options {
  const repoRoot = resolve(import.meta.dir, "../../..");
  const options: Options = {
    output: resolve(repoRoot, "target/v1-benchmarks/reproduction/e15-provekit"),
    campaign: "provekit-v1-cross-device",
    apk: resolve(
      repoRoot,
      "target/v1-benchmarks/e15-diagnostic-build/android/app/build/outputs/apk/debug/app-debug.apk",
    ),
    warmup: 1,
    samples: 5,
    timeoutSeconds: 7200,
    workloads: workloads.map(([name]) => name),
    rebootBeforeEach: false,
    passportSingleThread: false,
    workerProcessSuffix: ":mobench_worker",
  };
  for (let index = 0; index < args.length; index++) {
    const flag = args[index]!;
    if (flag === "--sequential") continue;
    if (flag === "--reboot-before-each") {
      options.rebootBeforeEach = true;
      continue;
    }
    if (flag === "--passport-single-thread") {
      options.passportSingleThread = true;
      continue;
    }
    const value = args[++index];
    if (!value) throw new Error(`missing value for ${flag}`);
    if (flag === "--output") options.output = resolve(value);
    else if (flag === "--campaign") options.campaign = value;
    else if (flag === "--apk") options.apk = resolve(value);
    else if (flag === "--warmup") options.warmup = positiveInteger(value, flag);
    else if (flag === "--samples") options.samples = positiveInteger(value, flag);
    else if (flag === "--timeout-seconds") {
      options.timeoutSeconds = positiveInteger(value, flag);
    } else if (flag === "--workloads") {
      const selected = value.split(",").filter(Boolean);
      const known = new Set(workloads.map(([name]) => name));
      const unknown = selected.filter((name) => !known.has(name));
      if (selected.length === 0 || unknown.length > 0) {
        throw new Error(
          `${flag} must be a comma-separated subset of ${[...known].join(",")}`,
        );
      }
      options.workloads = selected;
    } else if (flag === "--worker-process-suffix") {
      if (!/^:[A-Za-z0-9_]+$/.test(value)) {
        throw new Error(`${flag} must match :[A-Za-z0-9_]+`);
      }
      options.workerProcessSuffix = value;
    } else {
      throw new Error(`unknown argument: ${flag}`);
    }
  }
  return options;
}

function adbCommand(): string[] {
  const adb =
    process.env.ADB ??
    resolve(
      process.env.ANDROID_HOME ??
        process.env.ANDROID_SDK_ROOT ??
        resolve(process.env.HOME!, "Library/Android/sdk"),
      "platform-tools/adb",
    );
  const command = [adb];
  if (process.env.ANDROID_SERIAL) command.push("-s", process.env.ANDROID_SERIAL);
  return command;
}

async function command(
  args: string[],
  allowFailure = false,
  timeoutMs?: number,
): Promise<string> {
  const child = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
  let timedOut = false;
  const timer =
    timeoutMs === undefined
      ? undefined
      : setTimeout(() => {
          timedOut = true;
          child.kill();
        }, timeoutMs);
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (timer !== undefined) clearTimeout(timer);
  if (timedOut) {
    throw new Error(`${args.join(" ")} timed out after ${timeoutMs} ms`);
  }
  if (exitCode !== 0 && !allowFailure) {
    throw new Error(`${args.join(" ")} failed (${exitCode})\n${stderr}\n${stdout}`);
  }
  return `${stdout}${stderr}`;
}

async function logcat(adb: string[]): Promise<string> {
  return command(
    [
      ...adb,
      "logcat",
      "-d",
      "-v",
      "epoch",
      "BenchRunner:I",
      "lowmemorykiller:I",
      "ActivityManager:I",
      "AndroidRuntime:E",
      "libc:E",
      "DEBUG:I",
      "*:S",
    ],
    false,
    120_000,
  );
}

async function workerPid(adb: string[], workerProcessSuffix: string): Promise<string> {
  return (
    await command(
      [...adb, "shell", "pidof", `dev.world.benchmobile${workerProcessSuffix}`],
      true,
    )
  ).trim();
}

async function waitForPackageRemoval(adb: string[]): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    const path = await command(
      [...adb, "shell", "pm", "path", "dev.world.benchmobile"],
      true,
    );
    if (path.trim() === "") return;
    await Bun.sleep(500);
  }
  throw new Error("timed out waiting for dev.world.benchmobile removal");
}

async function rebootDevice(adb: string[]): Promise<void> {
  await command([...adb, "reboot"]);
  await command([...adb, "wait-for-device"]);
  for (let attempt = 0; attempt < 180; attempt++) {
    const completed = await command(
      [...adb, "shell", "getprop", "sys.boot_completed"],
      true,
    );
    if (completed.trim() === "1") {
      await command([...adb, "shell", "input", "keyevent", "82"], true);
      await Bun.sleep(3000);
      return;
    }
    await Bun.sleep(1000);
  }
  throw new Error("timed out waiting for the E15 to finish rebooting");
}

async function runWorkload(
  adb: string[],
  options: Options,
  workload: string,
  functionName: string,
) {
  // Android marks a process as bad after a native crash and may refuse to
  // launch the worker for later workloads even after `am force-stop` or an
  // in-place reinstall. A fresh package install clears that quarantine and is
  // outside every measured benchmark interval.
  await command([...adb, "uninstall", "dev.world.benchmobile"], true);
  await command([...adb, "uninstall", "dev.world.benchmobile.test"], true);
  await waitForPackageRemoval(adb);
  await command([...adb, "install", "-r", "-t", options.apk]);
  const startCommand = [
    ...adb,
    "shell",
    "am",
    "start",
    "-W",
    "-n",
    "dev.world.benchmobile/.MainActivity",
    "--es",
    "bench_function",
    functionName,
    "--ei",
    "bench_iterations",
    String(options.samples),
    "--ei",
    "bench_warmup",
    String(options.warmup),
    "--el",
    "bench_timeout_secs",
    String(options.timeoutSeconds),
    "--el",
    "bench_heartbeat_interval_secs",
    "10",
  ];
  let log = "";
  let workerDied = false;
  for (let launchAttempt = 0; launchAttempt < 2; launchAttempt++) {
    await command([...adb, "logcat", "-c"]);
    await command([...adb, "shell", "am", "force-stop", "dev.world.benchmobile"]);
    await command(startCommand);
    const deadline = Date.now() + options.timeoutSeconds * 1000;
    let observedWorker = false;
    while (Date.now() < deadline) {
      log = await logcat(adb);
      if (log.includes("BENCH_JSON_END") || log.includes("BENCH_FAILURE_JSON ")) break;
      const pid = await workerPid(adb, options.workerProcessSuffix);
      if (pid !== "") {
        observedWorker = true;
      } else if (observedWorker) {
        await Bun.sleep(2000);
        log = await logcat(adb);
        if (!log.includes("BENCH_JSON_END") && !log.includes("BENCH_FAILURE_JSON ")) {
          workerDied = true;
        }
        break;
      }
      await Bun.sleep(2000);
    }
    const failure = parseFailureJson(log) as { message?: string } | null;
    if (
      launchAttempt === 0 &&
      failure?.message?.includes("process is bad")
    ) {
      // ActivityManager's bad-process quarantine is keyed by process name and
      // can survive reinstall/reboot briefly. Its backoff expires after about
      // one minute; retrying the same installed APK preserves artifact identity.
      await Bun.sleep(65_000);
      workerDied = false;
      continue;
    }
    break;
  }
  const logPath = resolve(options.output, `${workload}.logcat.txt`);
  await Bun.write(logPath, log);
  if (log.includes("BENCH_JSON_END")) {
    return {
      workload,
      function: functionName,
      status: "ok",
      report: parseBenchJson(log),
      evidence_path: logPath,
    };
  }
  const failure = parseFailureJson(log);
  return {
    workload,
    function: functionName,
    status: failure ? "runtime_failed" : workerDied ? "crashed" : "timed_out",
    failure:
      failure ??
      (workerDied
        ? {
            schema_version: 1,
            kind: "worker_died",
            message:
              "isolated benchmark worker exited before emitting a result; inspect retained logcat for LMK or crash evidence",
          }
        : null),
    evidence_path: logPath,
  };
}

if (import.meta.main) {
  const options = parseArgs(process.argv.slice(2));
  if (!(await Bun.file(options.apk).exists())) throw new Error(`missing APK: ${options.apk}`);
  await mkdir(options.output, { recursive: true });
  const adb = adbCommand();
  const devices = await command([...adb, "devices", "-l"]);
  const selectedSerial = process.env.ANDROID_SERIAL;
  const connected = devices
    .split(/\r?\n/)
    .filter(
      (line) =>
        /\sdevice(?:\s|$)/.test(line) &&
        (!selectedSerial || line.startsWith(`${selectedSerial}\t`) || line.startsWith(`${selectedSerial} `)),
    );
  if (connected.length !== 1) {
    throw new Error(
      `expected exactly one authorized E15${selectedSerial ? ` matching ${selectedSerial}` : ""}, found ${connected.length}\n${devices}`,
    );
  }
  const identity = Object.fromEntries(
    await Promise.all(
      [
        ["manufacturer", "ro.product.manufacturer"],
        ["model", "ro.product.model"],
        ["os", "ro.build.version.release"],
        ["abi", "ro.product.cpu.abi"],
        ["abilist", "ro.product.cpu.abilist"],
        ["abilist64", "ro.product.cpu.abilist64"],
        ["zygote", "ro.zygote"],
      ].map(async ([key, property]) => [
        key,
        (await command([...adb, "shell", "getprop", property])).trim(),
      ]),
    ),
  );
  await Bun.write(
    resolve(options.output, "device.json"),
    `${JSON.stringify({ captured_at_utc: new Date().toISOString(), ...identity }, null, 2)}\n`,
  );
  const results = [];
  for (const [workload, functionName] of workloads.filter(([name]) =>
    options.workloads.includes(name)
  )) {
    const selectedFunction =
      workload === "passport" && options.passportSingleThread
        ? "bench_mobile::bench_passport_complete_age_check_prove_single_thread"
        : functionName;
    try {
      if (options.rebootBeforeEach) await rebootDevice(adb);
      results.push(await runWorkload(adb, options, workload, selectedFunction));
    } catch (error) {
      const evidencePath = resolve(options.output, `${workload}.orchestration-failure.json`);
      const failure = orchestrationFailure(
        workload,
        selectedFunction,
        error,
        evidencePath,
      );
      await Bun.write(evidencePath, `${JSON.stringify(failure, null, 2)}\n`);
      results.push(failure);
    }
  }
  const output = {
    schema_version: 1,
    campaign_id: options.campaign,
    generated_at_utc: new Date().toISOString(),
    sampling: { warmup: options.warmup, measured: options.samples, sequential: true },
    device: identity,
    apk: {
      path: options.apk,
      sha256: new Bun.CryptoHasher("sha256").update(await Bun.file(options.apk).bytes()).digest("hex"),
      bytes: Bun.file(options.apk).size,
    },
    results,
  };
  const outputPath = resolve(options.output, "results.json");
  await Bun.write(outputPath, `${JSON.stringify(output, null, 2)}\n`);
  console.log(outputPath);
}
