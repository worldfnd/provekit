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
exports.abi = exports.acvm = exports.Noir = exports.and = exports.xor = exports.blake2s256 = exports.ecdsa_secp256k1_verify = exports.ecdsa_secp256r1_verify = void 0;
const acvm = __importStar(require("@noir-lang/acvm_js"));
exports.acvm = acvm;
const abi = __importStar(require("@noir-lang/noirc_abi"));
exports.abi = abi;
var acvm_js_1 = require("@noir-lang/acvm_js");
Object.defineProperty(exports, "ecdsa_secp256r1_verify", { enumerable: true, get: function () { return acvm_js_1.ecdsa_secp256r1_verify; } });
Object.defineProperty(exports, "ecdsa_secp256k1_verify", { enumerable: true, get: function () { return acvm_js_1.ecdsa_secp256k1_verify; } });
Object.defineProperty(exports, "blake2s256", { enumerable: true, get: function () { return acvm_js_1.blake2s256; } });
Object.defineProperty(exports, "xor", { enumerable: true, get: function () { return acvm_js_1.xor; } });
Object.defineProperty(exports, "and", { enumerable: true, get: function () { return acvm_js_1.and; } });
var program_js_1 = require("./program.cjs");
Object.defineProperty(exports, "Noir", { enumerable: true, get: function () { return program_js_1.Noir; } });
