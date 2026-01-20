import { Logger, PluginSyntaxError } from '@web/dev-server-core';
export declare class DevServerLogger implements Logger {
    private debugLogging;
    private onSyntaxError;
    constructor(debugLogging: boolean, onSyntaxError: (msg: string) => void);
    log(...messages: unknown[]): void;
    debug(...messages: unknown[]): void;
    error(...messages: unknown[]): void;
    warn(...messages: unknown[]): void;
    group(): void;
    groupEnd(): void;
    logSyntaxError(error: PluginSyntaxError): void;
}
//# sourceMappingURL=DevServerLogger.d.ts.map