import type { LogType } from "./types.js";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function timeString(): string {
  const now = new Date();
  return `[${now.getHours().toString().padStart(2, "0")}:${now.getMinutes().toString().padStart(2, "0")}:${now.getSeconds().toString().padStart(2, "0")}]`;
}

export class LogRenderer {
  constructor(private readonly container: HTMLElement) {}

  clear(): void {
    this.container.querySelectorAll(".log-line, .log-error-block").forEach((node) => node.remove());
  }

  log(message: string, type: LogType = "info"): void {
    const line = document.createElement("div");

    if (type === "error") {
      line.className = "log-error-block";
      line.innerHTML = `<strong>Error:</strong> ${escapeHtml(message)}`;
    } else if (type === "success") {
      line.className = "log-line log-success";
      line.innerHTML = `<span class="log-time">${timeString()}</span><span class="log-check">✓</span>${escapeHtml(message)}`;
    } else {
      line.className = type === "warn" ? "log-line log-error" : "log-line";
      line.innerHTML = `<span class="log-time">${timeString()}</span><span class="log-arrow">→</span>${escapeHtml(message)}`;
    }

    this.append(line);
  }

  logCircuitSelection(labelHtml: string, message: string): void {
    const line = document.createElement("div");
    line.className = "log-line";
    line.innerHTML = `<span class="log-time">${timeString()}</span><span class="log-arrow">→</span>${labelHtml} ${escapeHtml(message)}`;
    this.append(line);
  }

  async copyToClipboard(): Promise<void> {
    const text = Array.from(this.container.querySelectorAll<HTMLElement>(".log-line, .log-error-block"))
      .map((node) => node.innerText)
      .join("\n");

    await navigator.clipboard.writeText(text);
  }

  private append(node: HTMLElement): void {
    this.container.appendChild(node);
    this.container.scrollTop = this.container.scrollHeight;
  }
}
