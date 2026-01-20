import { Plugin } from '@web/dev-server-core';
import { DevServerLogger } from './DevServerLogger.js';
export interface LoggerArgs {
    debugLogging: boolean;
    clearTerminalOnReload: boolean;
    logStartMessage: boolean;
}
export declare function createLogger(args: LoggerArgs): {
    logger: DevServerLogger;
    loggerPlugin: Plugin;
};
//# sourceMappingURL=createLogger.d.ts.map