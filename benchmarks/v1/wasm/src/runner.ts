type RunnerStatus = "ready" | "running" | "complete" | "error";

interface RunnerState {
  status: RunnerStatus;
  result?: unknown;
  error?: string;
}

declare global {
  interface Window {
    __MOBENCH_STATE__: RunnerState;
  }
}

const form = document.querySelector<HTMLFormElement>("#controls");
const status = document.querySelector<HTMLElement>("#status");
const output = document.querySelector<HTMLElement>("#output");
const runButton = document.querySelector<HTMLButtonElement>("#run");
const warmupInput = document.querySelector<HTMLInputElement>("#warmup");
const iterationsInput = document.querySelector<HTMLInputElement>("#iterations");

if (!form || !status || !output || !runButton || !warmupInput || !iterationsInput) {
  throw new Error("benchmark controls are missing");
}

window.__MOBENCH_STATE__ = { status: "ready" };
const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });

function setState(state: RunnerState): void {
  window.__MOBENCH_STATE__ = state;
  status.textContent =
    state.status === "running"
      ? "Running… keep this tab in the foreground."
      : state.status === "complete"
        ? "Complete."
        : state.status === "error"
          ? `Failed: ${state.error}`
          : "Ready.";
  output.textContent = state.result
    ? JSON.stringify(state.result, null, 2)
    : state.error ?? "";
  runButton.disabled = state.status === "running";
}

function boundedInteger(input: HTMLInputElement, minimum: number, maximum: number): number {
  const value = Number.parseInt(input.value, 10);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${input.id} must be between ${minimum} and ${maximum}`);
  }
  return value;
}

function run(): void {
  try {
    const warmup = boundedInteger(warmupInput, 0, 10);
    const iterations = boundedInteger(iterationsInput, 1, 20);
    setState({ status: "running" });
    worker.postMessage({ type: "run", warmup, iterations });
  } catch (error) {
    setState({ status: "error", error: error instanceof Error ? error.message : String(error) });
  }
}

worker.addEventListener("message", (event: MessageEvent) => {
  const message = event.data as { type?: string; result?: unknown; error?: string };
  if (message.type === "complete") {
    setState({ status: "complete", result: message.result });
  } else if (message.type === "error") {
    setState({ status: "error", error: message.error ?? "unknown worker error" });
  }
});

worker.addEventListener("error", (event) => {
  setState({ status: "error", error: event.message });
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  run();
});

const query = new URLSearchParams(location.search);
if (query.get("autorun") === "1") {
  warmupInput.value = query.get("warmup") ?? "0";
  iterationsInput.value = query.get("iterations") ?? "1";
  run();
}
