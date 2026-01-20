"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Noir = void 0;
const witness_generation_js_1 = require("./witness_generation.cjs");
const noirc_abi_1 = __importStar(require("@noir-lang/noirc_abi"));
const acvm_js_1 = __importStar(require("@noir-lang/acvm_js"));
class Noir {
    circuit;
    constructor(circuit) {
        this.circuit = circuit;
    }
    /** @ignore */
    async init() {
        // If these are available, then we are in the
        // web environment. For the node environment, this
        // is a no-op.
        if (typeof noirc_abi_1.default === 'function') {
            await Promise.all([(0, noirc_abi_1.default)(), (0, acvm_js_1.default)()]);
        }
    }
    /**
     * @description
     * Allows to execute a circuit to get its witness and return value.
     *
     * @example
     * ```typescript
     * async execute(inputs)
     * ```
     */
    async execute(inputs, foreignCallHandler) {
        await this.init();
        const witness_stack = await (0, witness_generation_js_1.generateWitness)(this.circuit, inputs, foreignCallHandler);
        const main_witness = witness_stack[0].witness;
        const { return_value: returnValue } = (0, noirc_abi_1.abiDecode)(this.circuit.abi, main_witness);
        return { witness: (0, acvm_js_1.compressWitnessStack)(witness_stack), returnValue };
    }
}
exports.Noir = Noir;
