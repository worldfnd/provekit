"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TestRunnerLogger = void 0;
class TestRunnerLogger {
    constructor(debugLogging = false) {
        this.debugLogging = debugLogging;
        this.loggedSyntaxErrors = new Map();
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
        let errors = this.loggedSyntaxErrors.get(filePath);
        if (!errors) {
            errors = [];
            this.loggedSyntaxErrors.set(filePath, errors);
        }
        else if (errors.find(e => e.code === code && e.message === message && e.column === column && e.line === line)) {
            // dedupe syntax errors we already logged
            return;
        }
        errors.push(error);
    }
    clearLoggedSyntaxErrors() {
        this.loggedSyntaxErrors = new Map();
    }
}
exports.TestRunnerLogger = TestRunnerLogger;
//# sourceMappingURL=TestRunnerLogger.js.map