"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logStartMessage = void 0;
const internal_ip_1 = __importDefault(require("internal-ip"));
const nanocolors_1 = require("nanocolors");
const createAddress = (config, host, path) => `http${config.http2 ? 's' : ''}://${host}:${config.port}${path}`;
function logNetworkAddress(config, logger, openPath) {
    try {
        const address = internal_ip_1.default.v4.sync();
        if (typeof address === 'string') {
            logger.log(`${(0, nanocolors_1.white)('Network:')}  ${(0, nanocolors_1.cyan)(createAddress(config, address, openPath))}`);
        }
    }
    catch (_a) {
        //
    }
}
function logStartMessage(config, logger) {
    var _a;
    const prettyHost = (_a = config.hostname) !== null && _a !== void 0 ? _a : 'localhost';
    let openPath = typeof config.open === 'string' ? config.open : '/';
    if (!openPath.startsWith('/')) {
        openPath = `/${openPath}`;
    }
    logger.log((0, nanocolors_1.bold)('Web Dev Server started...'));
    logger.log('');
    logger.group();
    logger.log(`${(0, nanocolors_1.white)('Root dir:')} ${(0, nanocolors_1.cyan)(config.rootDir)}`);
    logger.log(`${(0, nanocolors_1.white)('Local:')}    ${(0, nanocolors_1.cyan)(createAddress(config, prettyHost, openPath))}`);
    logNetworkAddress(config, logger, openPath);
    logger.groupEnd();
    logger.log('');
}
exports.logStartMessage = logStartMessage;
//# sourceMappingURL=logStartMessage.js.map