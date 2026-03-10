/**
 * ProveKit WASM Browser Demo
 *
 * Demonstrates zero-knowledge proof generation using ProveKit WASM bindings in the browser:
 * 1. Load compiled Noir circuit
 * 2. Generate witness using @noir-lang/noir_js (local web bundles)
 * 3. Generate proof using ProveKit WASM
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
    } else if (typeof obj === 'object' && obj !== null) {
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

/**
 * Convert a Noir witness map to the format expected by ProveKit WASM.
 */
function convertWitnessMap(witnessMap) {
  const result = {};
  if (witnessMap instanceof Map) {
    for (const [index, value] of witnessMap.entries()) {
      result[index] = value;
    }
  } else if (typeof witnessMap === "object" && witnessMap !== null) {
    for (const [index, value] of Object.entries(witnessMap)) {
      result[Number(index)] = value;
    }
  } else {
    throw new Error(`Unexpected witness map type: ${typeof witnessMap}`);
  }
  return result;
}

function getArtifactBase() {
  const circuit = window.activeCircuit || 'sha256';
  return `artifacts/${circuit}/`;
}

async function loadInputs() {
  const response = await fetch(getArtifactBase() + "inputs.json");
  if (!response.ok) {
    throw new Error("inputs.json not found. Run setup first.");
  }
  return response.json();
}

/**
 * TOML parser for Noir Prover.toml files (browser-side).
 * Handles inline tables { k = "v" }, arrays of inline tables,
 * multi-line arrays, dotted keys (a.b.c), and [section] headers.
 */

/** Split string by delimiter, respecting quoted strings and nested {} [] */
function splitTopLevel(str, delimiter) {
  const parts = [];
  let current = '';
  let inStr = false;
  let strCh = '';
  let braces = 0;
  let brackets = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (inStr) {
      current += ch;
      if (ch === strCh && str[i - 1] !== '\\') inStr = false;
      continue;
    }
    if (ch === '"' || ch === "'") { inStr = true; strCh = ch; current += ch; continue; }
    if (ch === '{') braces++;
    if (ch === '}') braces--;
    if (ch === '[') brackets++;
    if (ch === ']') brackets--;
    if (ch === delimiter && braces === 0 && brackets === 0) {
      parts.push(current);
      current = '';
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
  for (const pair of splitTopLevel(inner, ',')) {
    const t = pair.trim();
    if (!t) continue;
    const eq = t.indexOf('=');
    if (eq === -1) continue;
    result[t.slice(0, eq).trim()] = parseTomlValue(t.slice(eq + 1).trim());
  }
  return result;
}

function parseTomlArray(str) {
  const inner = str.slice(1, -1).trim();
  if (!inner) return [];
  return splitTopLevel(inner, ',')
    .map(el => el.trim())
    .filter(el => el.length > 0)
    .map(el => parseTomlValue(el));
}

function parseTomlValue(raw) {
  if (raw.startsWith('{') && raw.endsWith('}')) return parseInlineTable(raw);
  if (raw.startsWith('[') && raw.endsWith(']')) return parseTomlArray(raw);
  if ((raw.startsWith('"') && raw.endsWith('"')) ||
      (raw.startsWith("'") && raw.endsWith("'"))) return raw.slice(1, -1);
  return raw; // keep as string — noir_js expects string numbers
}

/** Set a value at a nested dotted path, creating intermediate objects */
function setNested(obj, path, val) {
  let cur = obj;
  for (let i = 0; i < path.length - 1; i++) {
    if (!(path[i] in cur) || typeof cur[path[i]] !== 'object' ||
        cur[path[i]] === null || Array.isArray(cur[path[i]])) {
      cur[path[i]] = {};
    }
    cur = cur[path[i]];
  }
  cur[path[path.length - 1]] = val;
}

function parseSimpleToml(content) {
  // Phase 1: Join multi-line arrays into single logical lines
  const logicalLines = [];
  const rawLines = content.split('\n');
  let buffer = '';
  let depth = 0;
  for (const rawLine of rawLines) {
    const stripped = rawLine.trim();
    if (!stripped || stripped.startsWith('#')) continue;
    if (depth > 0) {
      buffer += ' ' + stripped;
      for (const ch of stripped) {
        if (ch === '[') depth++;
        else if (ch === ']') depth--;
      }
      if (depth <= 0) { logicalLines.push(buffer); buffer = ''; depth = 0; }
      continue;
    }
    const eqIdx = stripped.indexOf('=');
    if (eqIdx !== -1) {
      const valPart = stripped.slice(eqIdx + 1).trim();
      let d = 0;
      for (const ch of valPart) { if (ch === '[') d++; else if (ch === ']') d--; }
      if (d > 0) { buffer = stripped; depth = d; continue; }
    }
    logicalLines.push(stripped);
  }

  // Phase 2: Parse logical lines into nested object
  const result = {};
  let section = null;
  for (const line of logicalLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const secMatch = trimmed.match(/^\[([^\]]+)\]$/);
    if (secMatch) { section = secMatch[1]; continue; }
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = parseTomlValue(trimmed.slice(eqIdx + 1).trim());
    const fullPath = section ? [section, ...key.split('.')] : key.split('.');
    setNested(result, fullPath, val);
  }
  return result;
}

// Global state
let provekit = null;
let circuitJson = null;
let proverBin = null;
let verifierBin = null;
let lastProofBytes = null;

async function initWasm() {
  try {
    updateStep(1, '<span class="spinner"></span>Loading...', "running");
    log("Loading ProveKit WASM module...");

    const wasmModule = await import("../pkg/provekit_wasm.js");
    const wasmBinary = await fetch("pkg/provekit_wasm_bg.wasm");
    const wasmBytes = await wasmBinary.arrayBuffer();
    await wasmModule.default(wasmBytes);

    if (wasmModule.initPanicHook) {
      wasmModule.initPanicHook();
    }

    const isIOS = /iPhone|iPad|iPod/.test(navigator.userAgent);
    const isAndroid = /Android/.test(navigator.userAgent);
    const isMobile = isIOS || isAndroid;
    const maxThreads = navigator.hardwareConcurrency || 4;
    const threadCountEl = document.getElementById("threadCount");
    const hasSharedArrayBuffer = typeof SharedArrayBuffer !== 'undefined';

    // iOS WebKit has unreliable WASM threading — don't even try
    if (isIOS) {
      log("📱 iOS detected - WebKit WASM threading is unreliable");
      log("Running in single-threaded mode (optimized for iOS)");
      if (threadCountEl) threadCountEl.textContent = 1;
    } else if (isAndroid && hasSharedArrayBuffer) {
      const androidThreads = Math.min(maxThreads, 4);
      log(`📱 Android detected, trying ${androidThreads} threads...`);
      try {
        await wasmModule.initThreadPool(androidThreads);
        log(`Thread pool ready (${androidThreads} workers)`);
        if (threadCountEl) threadCountEl.textContent = androidThreads;
      } catch (e) {
        log(`Thread pool failed: ${e.message}`, "warn");
        log("Falling back to single-threaded mode", "warn");
        if (threadCountEl) threadCountEl.textContent = 1;
      }
    } else if (!isMobile && hasSharedArrayBuffer) {
      try {
        log(`Initializing thread pool with ${maxThreads} workers...`);
        await wasmModule.initThreadPool(maxThreads);
        log(`Thread pool ready (${maxThreads} workers)`);
        if (threadCountEl) threadCountEl.textContent = maxThreads;
      } catch (e) {
        log(`Thread pool failed: ${e.message}`, "warn");
        log("Falling back to single-threaded mode", "warn");
        if (threadCountEl) threadCountEl.textContent = 1;
      }
    } else {
      if (!isMobile) {
        log("SharedArrayBuffer not available, running single-threaded", "warn");
      } else {
        log("Mobile: running in single-threaded mode");
      }
      if (threadCountEl) threadCountEl.textContent = 1;
    }

    provekit = wasmModule;
    log("Initializing noir_js WASM modules...");

    let attempts = 0;
    while (!window.Noir && attempts < 50) {
      await new Promise((r) => setTimeout(r, 100));
      attempts++;
    }

    if (!window.Noir) {
      throw new Error("Failed to load noir_js");
    }

    if (window.initNoir) {
      await window.initNoir();
    }

    log("noir_js initialized");
    updateStep(1, "Loaded", "success");
    runBtn.disabled = false;
    window.wasmReady = true;

  } catch (error) {
    log(`Error initializing WASM: ${error.message}`, "error");
    console.error(error);
    updateStep(1, "Failed", "error");
  }
}

async function runDemo() {
  runBtn.disabled = true;
  const logLines = logContainer.querySelectorAll('.log-line, .log-error-block');
  logLines.forEach(el => el.remove());

  for (let i = 2; i <= 5; i++) {
    updateStep(i, "Waiting...");
  }
  verifyBtn.disabled = true;
  lastProofBytes = null;

  let witnessTime = 0;
  let proofTime = 0;
  let witnessSize = 0;
  let proofSize = 0;
  let numConstraints = 0;
  let numWitnesses = 0;
  let inputs = {};
  let prover = null;
  try {
    updateStep(2, '<span class="spinner"></span>Loading artifacts...', "running");
    const isCustom = window.activeCircuit === 'custom';

    // --- Load artifacts (mode-specific) ---
    if (isCustom && window.customFiles) {
      log("Loading uploaded prover and verifier artifacts...");
      logMemory("Before loading artifacts");
      proverBin = await window.customFiles.prover.arrayBuffer();
      verifierBin = await window.customFiles.verifier.arrayBuffer();
    } else {
      const base = getArtifactBase();
      let circuitName = "unknown";
      try {
        const metadataResponse = await fetch(base + "metadata.json");
        if (metadataResponse.ok) {
          const metadata = await metadataResponse.json();
          circuitName = metadata.name || "unknown";
        }
      } catch (e) {
        // metadata.json is optional
      }
      log(`Circuit: ${circuitName}`);
      log("Loading prover (.pkp) and verifier (.pkv) artifacts...");
      logMemory("Before loading artifacts");
      const [proverResponse, verifierResponse] = await Promise.all([
        fetch(base + "prover.pkp"),
        fetch(base + "verifier.pkv"),
      ]);
      proverBin = await proverResponse.arrayBuffer();
      verifierBin = await verifierResponse.arrayBuffer();
    }

    // --- Common: log sizes, create prover, extract circuit ---
    log(`Prover artifact: ${(proverBin.byteLength / 1024 / 1024).toFixed(2)} MB`);
    log(`Verifier artifact: ${(verifierBin.byteLength / 1024 / 1024).toFixed(2)} MB`);
    logMemory("After loading artifacts", { proverBin, verifierBin });

    log("Creating Prover instance...");
    prover = new provekit.Prover(new Uint8Array(proverBin));
    proverBin = null;

    numConstraints = prover.getNumConstraints();
    numWitnesses = prover.getNumWitnesses();
    log(`Circuit: ${numConstraints.toLocaleString()} constraints, ${numWitnesses.toLocaleString()} witnesses`);

    const circuitBytes = prover.getCircuit();
    circuitJson = JSON.parse(new TextDecoder().decode(circuitBytes));
    log("Circuit extracted from prover artifact");
    logMemory("After creating Prover (freed proverBin)");
    updateStep(2, "Loaded", "success");

    // --- Load inputs (mode-specific) ---
    updateStep(3, '<span class="spinner"></span>Generating witness...', "running");
    if (isCustom && window.customFiles) {
      const inputsFile = window.customFiles.inputs;
      if (inputsFile.name.endsWith('.toml')) {
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

    // --- Generate witness ---
    log("Generating witness using noir_js...");
    logMemory("Before witness generation", { circuitJson, inputs });

    await new Promise((r) => setTimeout(r, 50)); // Let UI update

    const witnessStart = performance.now();
    const noir = new window.Noir(circuitJson);
    const { witness: compressedWitness } = await noir.execute(inputs);
    const witnessStack = window.decompressWitness(compressedWitness);
    const witnessMap = witnessStack[0].witness;
    witnessTime = performance.now() - witnessStart;

    const witnessObjSize = witnessMap instanceof Map
      ? witnessMap.size * 64
      : Object.keys(witnessMap).length * 64;
    log(`\u{1F4CA} Witness object: ~${(witnessObjSize / 1024).toFixed(0)} KB estimated`);
    logMemory("After witness generation");

    witnessSize =
      witnessMap instanceof Map
        ? witnessMap.size
        : Object.keys(witnessMap).length;
    log(`Witness size: ${witnessSize} elements`);
    log(`Witness generation time: ${witnessTime.toFixed(0)}ms`);

    updateStep(3, `Done (${witnessTime.toFixed(0)}ms)`, "success");

    // --- Generate proof ---
    updateStep(4, '<span class="spinner"></span>Generating proof...', "running");
    log("Converting witness format...");

    const convertedWitness = convertWitnessMap(witnessMap);
    log(`Converted ${Object.keys(convertedWitness).length} witness entries`);

    log("Generating proof (this may take a while)...");
    logMemory("Before proveBytes");

    await new Promise((r) => setTimeout(r, 50)); // Let UI update

    const proofStart = performance.now();
    log("Starting proof computation...");
    const proofBytes = prover.proveBytes(convertedWitness);
    logMemory("After proveBytes");
    proofTime = performance.now() - proofStart;

    proofSize = proofBytes.length;
    log(`Proof size: ${(proofSize / 1024).toFixed(1)} KB`);
    log(`Proving time: ${(proofTime / 1000).toFixed(2)}s`);

    updateStep(4, `Done (${(proofTime / 1000).toFixed(2)}s)`, "success");

    lastProofBytes = proofBytes;

    const totalTimeMs = witnessTime + proofTime;
    document.getElementById("totalTimeUi").textContent =
      `${(totalTimeMs / 1000).toFixed(2)}s`;
    document.getElementById("proofSizeUi").textContent =
      `${(proofSize / 1024).toFixed(1)} KB`;
    document.getElementById("constraintsUi").textContent =
      numConstraints.toLocaleString();
    document.getElementById("witnessesUi").textContent =
      numWitnesses.toLocaleString();

    const proofText = new TextDecoder().decode(proofBytes);
    const truncated =
      proofText.length > 2000
        ? proofText.substring(0, 2000) + "..."
        : proofText;
    const proofOutputEl = document.getElementById("proofOutput");
    if (proofOutputEl) proofOutputEl.textContent = truncated;
    const proofCardEl = document.getElementById("proofCard");
    if (proofCardEl) proofCardEl.style.display = "block";

    updateStep(5, "Ready \u2014 click Verify Proof");
    verifyBtn.disabled = false;
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
  } finally {
    runBtn.disabled = false;
  }
}

async function verifyProof() {
  if (!lastProofBytes || !verifierBin || !provekit) {
    log("No proof available. Generate a proof first.", "error");
    return;
  }

  verifyBtn.disabled = true;

  try {
    updateStep(5, '<span class="spinner"></span>Verifying...', "running");
    log("Creating verifier instance...");
    const verifier = new provekit.Verifier(new Uint8Array(verifierBin));
    log("Verifying proof...");

    await new Promise((r) => setTimeout(r, 50)); // Let UI update

    const verifyStart = performance.now();
    verifier.verifyBytes(lastProofBytes);
    const verifyTime = performance.now() - verifyStart;
    log(`Verification time: ${verifyTime.toFixed(0)}ms`);
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
  circuitJson = null;
  proverBin = null;
  verifierBin = null;
  lastProofBytes = null;

  for (let i = 2; i <= 5; i++) {
    updateStep(i, "Status: Waiting...");
  }

  document.getElementById("totalTimeUi").textContent = "-";
  document.getElementById("proofSizeUi").textContent = "-";
  document.getElementById("constraintsUi").textContent = "-";
  document.getElementById("witnessesUi").textContent = "-";

  if (provekit) runBtn.disabled = false;
  verifyBtn.disabled = true;

  log(`Switched to ${circuit.toUpperCase()} circuit`, "info");
}

initWasm();

window.runDemo = runDemo;
window.verifyProof = verifyProof;
window.onCircuitChanged = onCircuitChanged;
