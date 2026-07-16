// Mavros Buffer ABI v2 — the struct offsets and field encoding below mirror
// the Rust-side contract documented in tooling/provekit-wasm/src/prover.rs
// (look for `MAVROS_BUFFER_ABI_VERSION` and `prove_mavros_bytes`). Bump
// `MAVROS_BUFFER_ABI_VERSION` here and on the Rust side together when the
// layout changes — the version is sent across to the WASM prover for a
// handshake check.

interface WitnessLayout {
  algebraic_size: number;
  multiplicities_size: number;
  challenges_size: number;
  tables_data_size: number;
  lookups_data_size: number;
}

interface ConstraintsLayout {
  algebraic_size: number;
  tables_data_size: number;
  lookups_data_size: number;
}

interface MavrosTableInfo {
  multiplicitiesWitOffset: number;
  numIndices: number;
  kind: number;
  length: number;
  elemInversesWitnessSectionOffset: number;
  elemInversesConstraintSectionOffset: number;
}

export interface CompiledModuleRunner {
  readonly mavrosBufferAbiVersion: 2;
  runWitgen(
    inputFields: Uint8Array,
    witnessLayout: WitnessLayout,
    constraintsLayout: ConstraintsLayout,
  ): {
    outWitPreComm: Uint8Array;
    outWitPostComm: Uint8Array;
    outA: Uint8Array;
    outB: Uint8Array;
    outC: Uint8Array;
    tables: MavrosTableInfo[];
  };
  runWitgenInto(
    inputFields: Uint8Array,
    outWitPreComm: Uint8Array,
    outWitPostComm: Uint8Array,
    outA: Uint8Array,
    outB: Uint8Array,
    outC: Uint8Array,
    witnessLayout: WitnessLayout,
    constraintsLayout: ConstraintsLayout,
  ): {
    tables: MavrosTableInfo[];
  };
  runAd(
    coeffs: Uint8Array,
    witnessLayout: WitnessLayout,
    constraintsLayout: ConstraintsLayout,
  ): {
    outDa: Uint8Array;
    outDb: Uint8Array;
    outDc: Uint8Array;
  };
  runAdInto(
    coeffs: Uint8Array,
    outDa: Uint8Array,
    outDb: Uint8Array,
    outDc: Uint8Array,
    witnessLayout: WitnessLayout,
    constraintsLayout: ConstraintsLayout,
  ): void;
}

const FIELD_SIZE = 32;
const MAVROS_BUFFER_ABI_VERSION = 2 as const;
const WASM_STACK_SIZE_BYTES = 256 * 1024;
const WASM_STATIC_DATA_BYTES = 4096;

const TABLE_INFO_SLOT_SIZE = 24;
const TABLE_INFO_MULTS_BASE_PTR_OFFSET = 0;
const TABLE_INFO_INV_CNST_OFF_OFFSET = 4;
const TABLE_INFO_INV_WIT_OFF_OFFSET = 8;
const TABLE_INFO_NUM_INDICES_OFFSET = 12;
const TABLE_INFO_KIND_OFFSET = 16;
const TABLE_INFO_LENGTH_OFFSET = 20;

const WITGEN_WITNESS_PTR_OFFSET = 0;
const WITGEN_A_PTR_OFFSET = 4;
const WITGEN_A_BASE_PTR_OFFSET = 8;
const WITGEN_B_PTR_OFFSET = 12;
const WITGEN_C_PTR_OFFSET = 16;
const WITGEN_MULTS_CURSOR_PTR_OFFSET = 20;
const WITGEN_LOOKUPS_A_PTR_OFFSET = 24;
const WITGEN_LOOKUPS_B_PTR_OFFSET = 28;
const WITGEN_LOOKUPS_C_PTR_OFFSET = 32;
const WITGEN_INPUTS_PTR_OFFSET = 36;
const WITGEN_TABLES_LEN_OFFSET = 40;
const WITGEN_TABLES_CAP_OFFSET = 44;
const WITGEN_TABLES_PTR_OFFSET = 48;
const WITGEN_CURRENT_CNST_TABLES_OFF_OFFSET = 52;
const WITGEN_CURRENT_WIT_TABLES_OFF_OFFSET = 56;
const WITGEN_VM_STRUCT_SIZE = 64;

const AD_OUT_DA_PTR_OFFSET = 0;
const AD_OUT_DB_PTR_OFFSET = 4;
const AD_OUT_DC_PTR_OFFSET = 8;
const AD_COEFFS_PTR_OFFSET = 12;
const AD_CURRENT_WIT_OFF_OFFSET = 16;
const AD_COEFFS_BASE_PTR_OFFSET = 20;
const AD_CURRENT_LOOKUP_WIT_OFF_OFFSET = 24;
const AD_CURRENT_CNST_TABLES_OFF_OFFSET = 28;
const AD_CURRENT_WIT_TABLES_OFF_OFFSET = 32;
const AD_CURRENT_WIT_MULTIPLICITIES_OFF_OFFSET = 36;
const AD_VM_STRUCT_SIZE = 40;

type MavrosExports = WebAssembly.Exports;

function witnessSize(layout: WitnessLayout): number {
  return layout.algebraic_size
    + layout.multiplicities_size
    + layout.challenges_size
    + layout.tables_data_size
    + layout.lookups_data_size;
}

function witnessPreCommitmentSize(layout: WitnessLayout): number {
  return layout.algebraic_size + layout.multiplicities_size;
}

function witnessChallengesStart(layout: WitnessLayout): number {
  return witnessPreCommitmentSize(layout);
}

function witnessTablesDataStart(layout: WitnessLayout): number {
  return witnessChallengesStart(layout) + layout.challenges_size;
}

function witnessLookupsDataStart(layout: WitnessLayout): number {
  return witnessTablesDataStart(layout) + layout.tables_data_size;
}

function constraintsSize(layout: ConstraintsLayout): number {
  return layout.algebraic_size + layout.tables_data_size + layout.lookups_data_size;
}

function constraintsTablesDataStart(layout: ConstraintsLayout): number {
  return layout.algebraic_size;
}

function constraintsLookupsDataStart(layout: ConstraintsLayout): number {
  return constraintsTablesDataStart(layout) + layout.tables_data_size;
}

function pagesFor(bytes: number): number {
  return Math.max(4, Math.ceil(bytes / 65536));
}

function writeU32(view: DataView, ptr: number, value: number): void {
  view.setUint32(ptr, value, true);
}

function readU32(view: DataView, ptr: number): number {
  return view.getUint32(ptr, true);
}

function copyFieldRange(
  memory: WebAssembly.Memory,
  ptr: number,
  count: number,
  out: Uint8Array,
  label: string,
): void {
  const byteLength = count * FIELD_SIZE;
  if (out.byteLength !== byteLength) {
    throw new Error(`${label} buffer length ${out.byteLength} does not match ${byteLength}`);
  }
  out.set(new Uint8Array(memory.buffer, ptr, byteLength));
}

async function compileModule(bytes: Uint8Array): Promise<WebAssembly.Module> {
  return WebAssembly.compile(new Uint8Array(bytes).buffer);
}

export async function createMavrosRunner(
  programWasm: Uint8Array,
  legacyAdWasm?: Uint8Array,
): Promise<CompiledModuleRunner> {
  const programModule = await compileModule(programWasm);
  const adModule = legacyAdWasm ? await compileModule(legacyAdWasm) : programModule;
  const adEntryPoint = WebAssembly.Module.exports(adModule).some(
    ({ name, kind }) => name === "mavros_ad_main" && kind === "function",
  ) ? "mavros_ad_main" : "mavros_main";

  const runner: CompiledModuleRunner = {
    mavrosBufferAbiVersion: MAVROS_BUFFER_ABI_VERSION,

    runWitgen(inputFields, witnessLayout, constraintsLayout) {
      const witnessCount = witnessSize(witnessLayout);
      const constraintCount = constraintsSize(constraintsLayout);
      const preCommitmentCount = witnessPreCommitmentSize(witnessLayout);
      const outWitPreComm = new Uint8Array(preCommitmentCount * FIELD_SIZE);
      const outWitPostComm = new Uint8Array((witnessCount - preCommitmentCount) * FIELD_SIZE);
      const outA = new Uint8Array(constraintCount * FIELD_SIZE);
      const outB = new Uint8Array(constraintCount * FIELD_SIZE);
      const outC = new Uint8Array(constraintCount * FIELD_SIZE);
      const { tables } = runner.runWitgenInto(
        inputFields,
        outWitPreComm,
        outWitPostComm,
        outA,
        outB,
        outC,
        witnessLayout,
        constraintsLayout,
      );
      return {
        outWitPreComm,
        outWitPostComm,
        outA,
        outB,
        outC,
        tables,
      };
    },

    runWitgenInto(
      inputFields,
      outWitPreComm,
      outWitPostComm,
      outA,
      outB,
      outC,
      witnessLayout,
      constraintsLayout,
    ) {
      const witnessCount = witnessSize(witnessLayout);
      const constraintCount = constraintsSize(constraintsLayout);
      const preCommitmentCount = witnessPreCommitmentSize(witnessLayout);
      if (!Number.isInteger(inputFields.byteLength / FIELD_SIZE)) {
        throw new Error("Mavros input field buffer is not field-aligned");
      }

      const witnessBytes = witnessCount * FIELD_SIZE;
      const constraintBytes = constraintCount * FIELD_SIZE;
      const inputBytes = inputFields.byteLength;
      const tableInfoBytes = constraintsLayout.tables_data_size * TABLE_INFO_SLOT_SIZE;
      const hostBytes =
        WITGEN_VM_STRUCT_SIZE + witnessBytes + 3 * constraintBytes + inputBytes + tableInfoBytes;
      const pages = pagesFor(WASM_STACK_SIZE_BYTES + WASM_STATIC_DATA_BYTES + hostBytes);
      const { exports, memory } = instantiateWithMemorySync(programModule, pages, "mavros_main");

      const dataEnd = getDataEnd(exports);
      const dataOffset = (dataEnd + 15) & ~15;
      const vmStructPtr = dataOffset;
      const witnessPtr = vmStructPtr + WITGEN_VM_STRUCT_SIZE;
      const aPtr = witnessPtr + witnessBytes;
      const bPtr = aPtr + constraintBytes;
      const cPtr = bPtr + constraintBytes;
      const inputsPtr = cPtr + constraintBytes;
      const tablesPtr = inputsPtr + inputBytes;
      ensureMemory(memory, tablesPtr + tableInfoBytes);

      const view = new DataView(memory.buffer);
      const multsCursorPtr = witnessPtr + witnessLayout.algebraic_size * FIELD_SIZE;
      const lookupsA = aPtr + constraintsLookupsDataStart(constraintsLayout) * FIELD_SIZE;
      const lookupsB = bPtr + constraintsLookupsDataStart(constraintsLayout) * FIELD_SIZE;
      const lookupsC = cPtr + constraintsLookupsDataStart(constraintsLayout) * FIELD_SIZE;
      const currentCnstTablesOff = constraintsTablesDataStart(constraintsLayout);
      const currentWitTablesOff =
        witnessTablesDataStart(witnessLayout) - witnessChallengesStart(witnessLayout);

      writeU32(view, vmStructPtr + WITGEN_WITNESS_PTR_OFFSET, witnessPtr);
      writeU32(view, vmStructPtr + WITGEN_A_PTR_OFFSET, aPtr);
      writeU32(view, vmStructPtr + WITGEN_A_BASE_PTR_OFFSET, aPtr);
      writeU32(view, vmStructPtr + WITGEN_B_PTR_OFFSET, bPtr);
      writeU32(view, vmStructPtr + WITGEN_C_PTR_OFFSET, cPtr);
      writeU32(view, vmStructPtr + WITGEN_MULTS_CURSOR_PTR_OFFSET, multsCursorPtr);
      writeU32(view, vmStructPtr + WITGEN_LOOKUPS_A_PTR_OFFSET, lookupsA);
      writeU32(view, vmStructPtr + WITGEN_LOOKUPS_B_PTR_OFFSET, lookupsB);
      writeU32(view, vmStructPtr + WITGEN_LOOKUPS_C_PTR_OFFSET, lookupsC);
      writeU32(view, vmStructPtr + WITGEN_INPUTS_PTR_OFFSET, inputsPtr);
      writeU32(view, vmStructPtr + WITGEN_TABLES_CAP_OFFSET, constraintsLayout.tables_data_size);
      writeU32(view, vmStructPtr + WITGEN_TABLES_PTR_OFFSET, tablesPtr);
      writeU32(view, vmStructPtr + WITGEN_CURRENT_CNST_TABLES_OFF_OFFSET, currentCnstTablesOff);
      writeU32(view, vmStructPtr + WITGEN_CURRENT_WIT_TABLES_OFF_OFFSET, currentWitTablesOff);
      new Uint8Array(memory.buffer, inputsPtr, inputBytes).set(inputFields);

      callMavrosEntryPoint(exports, "mavros_main", vmStructPtr);
      const tablesLen = readU32(new DataView(memory.buffer), vmStructPtr + WITGEN_TABLES_LEN_OFFSET);
      if (tablesLen > constraintsLayout.tables_data_size) {
        throw new Error(`Mavros table registry overflow: ${tablesLen} > ${constraintsLayout.tables_data_size}`);
      }

      const tableView = new DataView(memory.buffer);
      const tables: MavrosTableInfo[] = Array.from({ length: tablesLen }, (_, index) => {
        const slot = tablesPtr + index * TABLE_INFO_SLOT_SIZE;
        const multsBase = readU32(tableView, slot + TABLE_INFO_MULTS_BASE_PTR_OFFSET);
        return {
          multiplicitiesWitOffset: (multsBase - witnessPtr) / FIELD_SIZE,
          numIndices: readU32(tableView, slot + TABLE_INFO_NUM_INDICES_OFFSET),
          kind: readU32(tableView, slot + TABLE_INFO_KIND_OFFSET),
          elemInversesConstraintSectionOffset: readU32(tableView, slot + TABLE_INFO_INV_CNST_OFF_OFFSET),
          elemInversesWitnessSectionOffset: readU32(tableView, slot + TABLE_INFO_INV_WIT_OFF_OFFSET),
          length: readU32(tableView, slot + TABLE_INFO_LENGTH_OFFSET),
        };
      });

      copyFieldRange(memory, witnessPtr, preCommitmentCount, outWitPreComm, "outWitPreComm");
      copyFieldRange(
        memory,
        witnessPtr + preCommitmentCount * FIELD_SIZE,
        witnessCount - preCommitmentCount,
        outWitPostComm,
        "outWitPostComm",
      );
      copyFieldRange(memory, aPtr, constraintCount, outA, "outA");
      copyFieldRange(memory, bPtr, constraintCount, outB, "outB");
      copyFieldRange(memory, cPtr, constraintCount, outC, "outC");
      return { tables };
    },

    runAd(coeffs, witnessLayout, constraintsLayout) {
      const witnessCount = witnessSize(witnessLayout);
      const outDa = new Uint8Array(witnessCount * FIELD_SIZE);
      const outDb = new Uint8Array(witnessCount * FIELD_SIZE);
      const outDc = new Uint8Array(witnessCount * FIELD_SIZE);
      runner.runAdInto(coeffs, outDa, outDb, outDc, witnessLayout, constraintsLayout);
      return { outDa, outDb, outDc };
    },

    runAdInto(coeffs, outDa, outDb, outDc, witnessLayout, constraintsLayout) {
      const witnessCount = witnessSize(witnessLayout);
      const constraintCount = constraintsSize(constraintsLayout);
      const expectedCoeffBytes = constraintCount * FIELD_SIZE;
      if (coeffs.byteLength !== expectedCoeffBytes) {
        throw new Error(`AD coeff length ${coeffs.byteLength} does not match ${constraintCount} fields`);
      }

      const witnessBytes = witnessCount * FIELD_SIZE;
      const coeffBytes = coeffs.byteLength;
      const hostBytes = AD_VM_STRUCT_SIZE + 3 * witnessBytes + coeffBytes;
      const pages = pagesFor(WASM_STACK_SIZE_BYTES + WASM_STATIC_DATA_BYTES + hostBytes);
      const { exports, memory } = instantiateWithMemorySync(adModule, pages, adEntryPoint);

      const dataEnd = getDataEnd(exports);
      const dataOffset = (dataEnd + 15) & ~15;
      const vmStructPtr = dataOffset;
      const daPtr = vmStructPtr + AD_VM_STRUCT_SIZE;
      const dbPtr = daPtr + witnessBytes;
      const dcPtr = dbPtr + witnessBytes;
      const coeffsPtr = dcPtr + witnessBytes;
      ensureMemory(memory, coeffsPtr + coeffBytes);

      new Uint8Array(memory.buffer, daPtr, 3 * witnessBytes).fill(0);
      new Uint8Array(memory.buffer, coeffsPtr, coeffBytes).set(coeffs);

      const view = new DataView(memory.buffer);
      writeU32(view, vmStructPtr + AD_OUT_DA_PTR_OFFSET, daPtr);
      writeU32(view, vmStructPtr + AD_OUT_DB_PTR_OFFSET, dbPtr);
      writeU32(view, vmStructPtr + AD_OUT_DC_PTR_OFFSET, dcPtr);
      writeU32(view, vmStructPtr + AD_COEFFS_PTR_OFFSET, coeffsPtr);
      writeU32(view, vmStructPtr + AD_CURRENT_WIT_OFF_OFFSET, 0);
      writeU32(view, vmStructPtr + AD_COEFFS_BASE_PTR_OFFSET, coeffsPtr);
      writeU32(view, vmStructPtr + AD_CURRENT_LOOKUP_WIT_OFF_OFFSET, witnessLookupsDataStart(witnessLayout));
      writeU32(view, vmStructPtr + AD_CURRENT_CNST_TABLES_OFF_OFFSET, constraintsTablesDataStart(constraintsLayout));
      writeU32(view, vmStructPtr + AD_CURRENT_WIT_TABLES_OFF_OFFSET, witnessTablesDataStart(witnessLayout));
      writeU32(view, vmStructPtr + AD_CURRENT_WIT_MULTIPLICITIES_OFF_OFFSET, witnessLayout.algebraic_size);

      callMavrosEntryPoint(exports, adEntryPoint, vmStructPtr);
      copyFieldRange(memory, daPtr, witnessCount, outDa, "outDa");
      copyFieldRange(memory, dbPtr, witnessCount, outDb, "outDb");
      copyFieldRange(memory, dcPtr, witnessCount, outDc, "outDc");
    },
  };
  return runner;
}

function instantiateWithMemorySync(
  module: WebAssembly.Module,
  pages: number,
  entryPoint: string,
): {
  exports: MavrosExports;
  memory: WebAssembly.Memory;
} {
  const memory = new WebAssembly.Memory({ initial: pages });
  const instance = new WebAssembly.Instance(module, { env: { memory } });
  const exports = instance.exports as MavrosExports;
  if (typeof exports[entryPoint] !== "function") {
    throw new Error(`Mavros WASM artifact does not export ${entryPoint}`);
  }
  if (!(exports["__data_end"] instanceof WebAssembly.Global)) {
    throw new Error("Mavros WASM artifact does not export __data_end");
  }
  return { exports, memory };
}

function getDataEnd(exports: MavrosExports): number {
  return Number((exports["__data_end"] as WebAssembly.Global).value);
}

function callMavrosEntryPoint(
  exports: MavrosExports,
  entryPoint: string,
  vmStructPtr: number,
): void {
  (exports[entryPoint] as (vmPtr: number) => void)(vmStructPtr);
}

function ensureMemory(memory: WebAssembly.Memory, byteLength: number): void {
  const current = memory.buffer.byteLength;
  if (byteLength <= current) {
    return;
  }
  memory.grow(Math.ceil((byteLength - current) / 65536));
}
