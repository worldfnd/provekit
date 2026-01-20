"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DevServerLogger = void 0;
const code_frame_1 = require("@babel/code-frame");
const path_1 = __importDefault(require("path"));
const nanocolors_1 = require("nanocolors");
class DevServerLogger {
    constructor(debugLogging, onSyntaxError) {
        this.debugLogging = debugLogging;
        this.onSyntaxError = onSyntaxError;
    }
    log(...messages) {
        console.log(...messages);
    }
    debug(...messages) {
        if (this.debugLogging) {
            console.debug(...messages);
        }
    }
    error(...messages) {
        console.error(...messages);
    }
    warn(...messages) {
        console.warn(...messages);
    }
    group() {
        console.group();
    }
    groupEnd() {
        console.groupEnd();
    }
    logSyntaxError(error) {
        const { message, code, filePath, column, line } = error;
        const highlightedResult = (0, code_frame_1.codeFrameColumns)(code, { start: { line, column } }, { highlightCode: true });
        const result = (0, code_frame_1.codeFrameColumns)(code, { start: { line, column } }, { highlightCode: false });
        const relativePath = path_1.default.relative(process.cwd(), filePath);
        console.error((0, nanocolors_1.red)(`Error while transforming ${(0, nanocolors_1.cyan)(relativePath)}: ${message}\n`));
        console.error(highlightedResult);
        console.error('');
        this.onSyntaxError(`Error while transforming ${relativePath}: ${message}` + `\n\n${result}\n\n`);
    }
}
exports.DevServerLogger = DevServerLogger;
//# sourceMappingURL=DevServerLogger.js.map