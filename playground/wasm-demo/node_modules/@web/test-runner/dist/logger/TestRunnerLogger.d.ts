import { Logger, ErrorWithLocation } from '@web/test-runner-core';
export declare class TestRunnerLogger implements Logger {
    private debugLogging;
    loggedSyntaxErrors: Map<string, ErrorWithLocation[]>;
    constructor(debugLogging?: boolean);
    log(...messages: unknown[]): void;
    debug(...messages: unknown[]): void;
    error(...messages: unknown[]): void;
    warn(...messages: unknown[]): void;
    group(): void;
    groupEnd(): void;
    logSyntaxError(error: ErrorWithLocation): void;
    clearLoggedSyntaxErrors(): void;
}
//# sourceMappingURL=TestRunnerLogger.d.ts.map