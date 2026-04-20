import { Verity, Backend } from "@atheonxyz/verity";
import initProvekitInspector, {
  Prover as ProvekitInspectorProver,
} from "../node_modules/@atheonxyz/verity/dist/wasm/provekit_wasm.js";

/**
 * ProveKit browser demo.
 *
 * Preserves the existing demo UX while routing proving and verification
 * through an internal proof runtime adapter.
 */

// DOM elements
const logContainer = document.getElementById("logContainer");
const runBtn = document.getElementById("runBtn");
const verifyBtn = document.getElementById("verifyBtn");

function log(msg, type = "info") {
  const line = document.createElement("div");
  line.className = `log-line log-${type}`;
  line.textContent = msg;
  logContainer.appendChild(line);
  logContainer.scrollTop = logContainer.scrollHeight;
}

function updateStep(step, status, statusClass = "") {
  const el = document.getElementById(`step${step}-status`);
  if (el) {
    el.innerHTML = status;
    el.className = `step-status ${statusClass}`;
  }
}

function logMemory(label, extras = {}) {
  let msg = `📊 ${label}`;

  for (const [name, obj] of Object.entries(extras)) {
    if (obj instanceof ArrayBuffer) {
      msg += ` | ${name}: ${(obj.byteLength / 1024 / 1024).toFixed(2)} MB`;
    } else if (obj instanceof Uint8Array) {
      msg += ` | ${name}: ${(obj.byteLength / 1024 / 1024).toFixed(2)} MB`;
    } else if (typeof obj === "object" && obj !== null) {
      const jsonSize = JSON.stringify(obj).length;
      msg += ` | ${name}: ~${(jsonSize / 1024).toFixed(0)} KB`;
    }
  }

  if (performance.memory) {
    const used = (performance.memory.usedJSHeapSize / 1024 / 1024).toFixed(1);
    msg += ` | heap: ${used} MB`;
  }

  log(msg, "info");
}

function getArtifactBase() {
  const circuit = window.activeCircuit || "sha256";
  return `artifacts/${circuit}/`;
}

async function loadInputs() {
  const response = await fetch(getArtifactBase() + "inputs.json");
  if (!response.ok) {
    throw new Error("inputs.json not found. Run setup first.");
  }
  return response.json();
}

async function loadMetadata(base) {
  try {
    const metadataResponse = await fetch(base + "metadata.json");
    if (!metadataResponse.ok) {
      return null;
    }
    return await metadataResponse.json();
  } catch {
    return null;
  }
}

let provekitInspectorReady = null;

async function ensureProvekitInspector() {
  if (!provekitInspectorReady) {
    provekitInspectorReady = (async () => {
      await initProvekitInspector();
    })();
  }
  await provekitInspectorReady;
}

async function readCircuitStatsFromPkp(proverBytes) {
  await ensureProvekitInspector();
  const inspector = new ProvekitInspectorProver(proverBytes);
  try {
    return {
      constraints: inspector.getNumConstraints(),
      witnesses: inspector.getNumWitnesses(),
    };
  } finally {
    inspector.free();
  }
}

/**
 * TOML parser for Noir Prover.toml files (browser-side).
 * Handles inline tables { k = "v" }, arrays of inline tables,
 * multi-line arrays, dotted keys (a.b.c), and [section] headers.
 */
function splitTopLevel(str, delimiter) {
  const parts = [];
  let current = "";
  let inStr = false;
  let strCh = "";
  let braces = 0;
  let brackets = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (inStr) {
      current += ch;
      if (ch === strCh && str[i - 1] !== "\\") inStr = false;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inStr = true;
      strCh = ch;
      current += ch;
      continue;
    }
    if (ch === "{") braces++;
    if (ch === "}") braces--;
    if (ch === "[") brackets++;
    if (ch === "]") brackets--;
    if (ch === delimiter && braces === 0 && brackets === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current);
  return parts;
}

function parseInlineTable(str) {
  const inner = str.slice(1, -1).trim();
  if (!inner) return {};
  const result = {};
  for (const pair of splitTopLevel(inner, ",")) {
    const t = pair.trim();
    if (!t) continue;
    const eq = t.indexOf("=");
    if (eq === -1) continue;
    result[t.slice(0, eq).trim()] = parseTomlValue(t.slice(eq + 1).trim());
  }
  return result;
}

function parseTomlArray(str) {
  const inner = str.slice(1, -1).trim();
  if (!inner) return [];
  return splitTopLevel(inner, ",")
    .map((el) => el.trim())
    .filter((el) => el.length > 0)
    .map((el) => parseTomlValue(el));
}

function parseTomlValue(raw) {
  if (raw.startsWith("{") && raw.endsWith("}")) return parseInlineTable(raw);
  if (raw.startsWith("[") && raw.endsWith("]")) return parseTomlArray(raw);
  if (
    (raw.startsWith('"') && raw.endsWith('"')) ||
    (raw.startsWith("'") && raw.endsWith("'"))
  ) {
    return raw.slice(1, -1);
  }
  return raw;
}

function setNested(obj, path, val) {
  let cur = obj;
  for (let i = 0; i < path.length - 1; i++) {
    if (
      !(path[i] in cur) ||
      typeof cur[path[i]] !== "object" ||
      cur[path[i]] === null ||
      Array.isArray(cur[path[i]])
    ) {
      cur[path[i]] = {};
    }
    cur = cur[path[i]];
  }
  cur[path[path.length - 1]] = val;
}

function parseSimpleToml(content) {
  const logicalLines = [];
  const rawLines = content.split("\n");
  let buffer = "";
  let depth = 0;
  for (const rawLine of rawLines) {
    const stripped = rawLine.trim();
    if (!stripped || stripped.startsWith("#")) continue;
    if (depth > 0) {
      buffer += " " + stripped;
      for (const ch of stripped) {
        if (ch === "[") depth++;
        else if (ch === "]") depth--;
      }
      if (depth <= 0) {
        logicalLines.push(buffer);
        buffer = "";
        depth = 0;
      }
      continue;
    }
    const eqIdx = stripped.indexOf("=");
    if (eqIdx !== -1) {
      const valPart = stripped.slice(eqIdx + 1).trim();
      let d = 0;
      for (const ch of valPart) {
        if (ch === "[") d++;
        else if (ch === "]") d--;
      }
      if (d > 0) {
        buffer = stripped;
        depth = d;
        continue;
      }
    }
    logicalLines.push(stripped);
  }

  const result = {};
  let section = null;
  for (const line of logicalLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const secMatch = trimmed.match(/^\[([^\]]+)\]$/);
    if (secMatch) {
      section = secMatch[1];
      continue;
    }
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = parseTomlValue(trimmed.slice(eqIdx + 1).trim());
    const fullPath = section ? [section, ...key.split(".")] : key.split(".");
    setNested(result, fullPath, val);
  }
  return result;
}

function updateMetrics(metadata, proofSize, totalTimeMs) {
  document.getElementById("totalTimeUi").textContent = `${(totalTimeMs / 1000).toFixed(2)}s`;
  document.getElementById("proofSizeUi").textContent = `${(proofSize / 1024).toFixed(1)} KB`;

  const constraintsValue =
    typeof metadata?.constraints === "number" ? metadata.constraints.toLocaleString() : "—";
  const witnessesValue =
    typeof metadata?.witnesses === "number" ? metadata.witnesses.toLocaleString() : "—";

  document.getElementById("constraintsUi").textContent = constraintsValue;
  document.getElementById("witnessesUi").textContent = witnessesValue;
}

function renderProofPreview(proof) {
  const proofText = new TextDecoder().decode(proof.data);
  const truncated = proofText.length > 2000 ? `${proofText.substring(0, 2000)}...` : proofText;
  const proofOutputEl = document.getElementById("proofOutput");
  if (proofOutputEl) proofOutputEl.textContent = truncated;
  const proofCardEl = document.getElementById("proofCard");
  if (proofCardEl) proofCardEl.style.display = "block";

  try {
    const proofJson = JSON.parse(proofText);
    const pi = proofJson.public_inputs;
    if (pi && pi.length > 0) {
      const values = pi.map((hex) => {
        const be = hex.match(/.{2}/g).slice().reverse().join("");
        return BigInt(`0x${be}`);
      });
      const allBytes = values.every((v) => v < 256n);
      if (allBytes) {
        const hexStr = values.map((v) => v.toString(16).padStart(2, "0")).join("");
        log(`Public inputs (${pi.length}): 0x${hexStr}`);
      } else {
        log(`Public inputs (${pi.length}):`);
        for (let i = 0; i < values.length; i++) {
          log(`  [${i}]: 0x${values[i].toString(16)}`);
        }
      }
    }
  } catch {
    // Proof preview is best-effort only.
  }
}

let verity = null;
let lastProof = null;
let activeVerifier = null;

function resetProgressUi() {
  for (let i = 2; i <= 5; i++) {
    updateStep(i, "Waiting...");
  }
  document.getElementById("totalTimeUi").textContent = "-";
  document.getElementById("proofSizeUi").textContent = "-";
  document.getElementById("constraintsUi").textContent = "-";
  document.getElementById("witnessesUi").textContent = "-";
  const proofOutputEl = document.getElementById("proofOutput");
  if (proofOutputEl) proofOutputEl.textContent = "";
  const proofCardEl = document.getElementById("proofCard");
  if (proofCardEl) proofCardEl.style.display = "none";
}

function disposeActiveVerifier() {
  if (activeVerifier) {
    activeVerifier.dispose();
    activeVerifier = null;
  }
}

async function initWasm() {
  try {
    updateStep(1, '<span class="spinner"></span>Loading...', "running");
    log("Initializing proof runtime...");

    const isIOS = /iPhone|iPad|iPod/.test(navigator.userAgent);
    const isAndroid = /Android/.test(navigator.userAgent);
    const isMobile = isIOS || isAndroid;
    const hasSharedArrayBuffer = typeof SharedArrayBuffer !== "undefined";
    const maxThreads = navigator.hardwareConcurrency || 4;
    const threadCountEl = document.getElementById("threadCount");

    let threadSetting = false;
    let threadLabel = 1;

    if (isIOS) {
      log("📱 iOS detected - WebKit WASM threading is unreliable");
      log("Running in single-threaded mode (optimized for iOS)");
    } else if (!hasSharedArrayBuffer) {
      if (!isMobile) {
        log("SharedArrayBuffer not available, running single-threaded", "warn");
      } else {
        log("Mobile: running in single-threaded mode");
      }
    } else if (isAndroid) {
      threadSetting = Math.min(maxThreads, 4);
      threadLabel = threadSetting;
      log(`📱 Android detected, requesting ${threadSetting} worker threads...`);
    } else {
      threadSetting = maxThreads;
      threadLabel = threadSetting;
      log(`Requesting ${threadSetting} worker threads...`);
    }

    verity = await Verity.create(Backend.ProveKit, {
      threads: threadSetting,
    });

    if (threadCountEl) {
      threadCountEl.textContent = String(threadLabel);
    }

    log("Proof runtime initialized", "success");
    updateStep(1, "Loaded", "success");
    runBtn.disabled = false;
    window.wasmReady = true;
  } catch (error) {
    log(`Error initializing proof runtime: ${error.message}`, "error");
    console.error(error);
    updateStep(1, "Failed", "error");
  }
}

async function runDemo() {
  runBtn.disabled = true;
  const logLines = logContainer.querySelectorAll(".log-line, .log-error-block");
  logLines.forEach((el) => el.remove());
  resetProgressUi();

  verifyBtn.disabled = true;
  lastProof = null;
  disposeActiveVerifier();

  let prover = null;
  let verifier = null;
  let metadata = null;

  try {
    updateStep(2, '<span class="spinner"></span>Loading artifacts...', "running");
    const isCustom = window.activeCircuit === "custom";

    let proverBytes;
    let verifierBytes;
    let inputs = {};

    if (isCustom && window.customFiles) {
      log("Loading uploaded prover and verifier artifacts...");
      logMemory("Before loading artifacts");
      proverBytes = new Uint8Array(await window.customFiles.prover.arrayBuffer());
      verifierBytes = new Uint8Array(await window.customFiles.verifier.arrayBuffer());
    } else {
      const base = getArtifactBase();
      metadata = await loadMetadata(base);
      const circuitName = metadata?.name || "unknown";
      log(`Circuit: ${circuitName}`);
      log("Loading prover (.pkp) and verifier (.pkv) artifacts...");
      logMemory("Before loading artifacts");
      const [proverResponse, verifierResponse] = await Promise.all([
        fetch(base + "prover.pkp"),
        fetch(base + "verifier.pkv"),
      ]);

      if (!proverResponse.ok || !verifierResponse.ok) {
        throw new Error("Missing prover or verifier artifact. Run setup first.");
      }

      proverBytes = new Uint8Array(await proverResponse.arrayBuffer());
      verifierBytes = new Uint8Array(await verifierResponse.arrayBuffer());
    }

    log(`Prover artifact: ${(proverBytes.byteLength / 1024 / 1024).toFixed(2)} MB`);
    log(`Verifier artifact: ${(verifierBytes.byteLength / 1024 / 1024).toFixed(2)} MB`);
    logMemory("After loading artifacts", { proverBytes, verifierBytes });

    const circuitStats = await readCircuitStatsFromPkp(proverBytes);
    metadata = {
      ...metadata,
      ...circuitStats,
    };
    log(
      `Circuit: ${metadata.constraints.toLocaleString()} constraints, ${metadata.witnesses.toLocaleString()} witnesses`
    );

    log("Loading prover and verifier...");
    const loadStart = performance.now();
    [prover, verifier] = await Promise.all([
      verity.loadProver(proverBytes),
      verity.loadVerifier(verifierBytes),
    ]);
    const loadTime = performance.now() - loadStart;
    log(`Scheme load time: ${loadTime.toFixed(0)}ms`);
    updateStep(2, "Loaded", "success");

    updateStep(3, '<span class="spinner"></span>Preparing inputs...', "running");
    if (isCustom && window.customFiles) {
      const inputsFile = window.customFiles.inputs;
      if (inputsFile.name.endsWith(".toml")) {
        log("Parsing Prover.toml...");
        const tomlText = await inputsFile.text();
        inputs = parseSimpleToml(tomlText);
      } else {
        const inputsText = await inputsFile.text();
        inputs = JSON.parse(inputsText);
      }
    } else {
      log("Loading inputs...");
      inputs = await loadInputs();
    }

    log(`Inputs loaded (${Object.keys(inputs).length} top-level keys)`);
    logMemory("After preparing inputs", { inputs });
    updateStep(3, "Done", "success");

    updateStep(4, '<span class="spinner"></span>Generating proof...', "running");
    log("Generating proof...");
    logMemory("Before prove()", { proverBytes, inputs });

    await new Promise((resolve) => setTimeout(resolve, 50));

    const proofStart = performance.now();
    const proof = await prover.prove(inputs);
    const proofTime = performance.now() - proofStart;

    logMemory("After prove()", { proof: proof.data });
    log(`Proof size: ${(proof.size / 1024).toFixed(1)} KB`);
    log(`Proving time: ${(proofTime / 1000).toFixed(2)}s`);
    renderProofPreview(proof);

    lastProof = proof;
    activeVerifier = verifier;
    verifier = null;

    updateStep(4, `Done (${(proofTime / 1000).toFixed(2)}s)`, "success");
    updateMetrics(metadata, proof.size, proofTime);

    verifyBtn.disabled = false;
    updateStep(5, "Ready — click Verify Proof");
  } catch (error) {
    log(`Error: ${error.message}`, "error");
    console.error(error);

    for (let i = 2; i <= 4; i++) {
      const el = document.getElementById(`step${i}-status`);
      if (el && el.classList.contains("running")) {
        updateStep(i, "Failed", "error");
        break;
      }
    }

    if (verifier) verifier.dispose();
  } finally {
    if (prover) prover.dispose();
    runBtn.disabled = false;
  }
}

async function verifyProof() {
  if (!lastProof || !activeVerifier || !verity) {
    log("No proof available. Generate a proof first.", "error");
    return;
  }

  verifyBtn.disabled = true;

  try {
    updateStep(5, '<span class="spinner"></span>Verifying...', "running");
    log("Verifying proof...");

    await new Promise((resolve) => setTimeout(resolve, 50));

    const verifyStart = performance.now();
    const isValid = await activeVerifier.verify(lastProof);
    const verifyTime = performance.now() - verifyStart;

    log(`Verification time: ${verifyTime.toFixed(0)}ms`);
    if (!isValid) {
      log("Proof is invalid.", "error");
      updateStep(5, `Invalid (${verifyTime.toFixed(0)}ms)`, "error");
      return;
    }

    log("Proof verified successfully!", "success");
    updateStep(5, `Verified ✓ (${verifyTime.toFixed(0)}ms)`, "success");
  } catch (error) {
    log(`Verification error: ${error.message}`, "error");
    console.error(error);
    updateStep(5, "Failed", "error");
  } finally {
    verifyBtn.disabled = false;
  }
}

function onCircuitChanged(circuit) {
  lastProof = null;
  disposeActiveVerifier();
  resetProgressUi();

  if (verity) runBtn.disabled = false;
  verifyBtn.disabled = true;

  log(`Switched to ${circuit.toUpperCase()} circuit`, "info");
}

initWasm();

window.runDemo = runDemo;
window.verifyProof = verifyProof;
window.onCircuitChanged = onCircuitChanged;
