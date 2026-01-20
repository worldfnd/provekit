"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createLogger = void 0;
const DevServerLogger_js_1 = require("./DevServerLogger.js");
const logStartMessage_js_1 = require("./logStartMessage.js");
const CLEAR_COMMAND = process.platform === 'win32' ? '\x1B[2J\x1B[0f' : '\x1B[2J\x1B[H';
function createLogger(args) {
    let onSyntaxError;
    const logger = new DevServerLogger_js_1.DevServerLogger(args.debugLogging, msg => onSyntaxError === null || onSyntaxError === void 0 ? void 0 : onSyntaxError(msg));
    return {
        logger,
        loggerPlugin: {
            name: 'logger',
            serverStart({ config, logger, fileWatcher, webSockets }) {
                if (webSockets) {
                    onSyntaxError = function onSyntaxError(msg) {
                        webSockets.sendConsoleLog(msg);
                    };
                }
                function logStartup(skipClear = false) {
                    if (!skipClear && args.clearTerminalOnReload) {
                        process.stdout.write(CLEAR_COMMAND);
                    }
                    (0, logStartMessage_js_1.logStartMessage)(config, logger);
                }
                if (args.logStartMessage) {
                    logStartup(true);
                }
                if (args.clearTerminalOnReload) {
                    fileWatcher.addListener('change', () => logStartup());
                    fileWatcher.addListener('unlink', () => logStartup());
                }
            },
        },
    };
}
exports.createLogger = createLogger;
//# sourceMappingURL=createLogger.js.map