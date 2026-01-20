"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.readFileConfig = void 0;
const config_loader_1 = require("@web/config-loader");
const DevServerStartError_js_1 = require("../DevServerStartError.js");
/**
 * Reads the config from disk, defaults to process.cwd() + web-dev-server.config.{mjs,js,cjs} or
 * a custom config path.
 * @param customConfig the custom location to read the config from
 */
async function readFileConfig({ configName = 'web-dev-server.config', configPath, } = {}) {
    try {
        return await (0, config_loader_1.readConfig)(configName, typeof configPath === 'string' ? configPath : undefined);
    }
    catch (error) {
        if (error instanceof config_loader_1.ConfigLoaderError) {
            throw new DevServerStartError_js_1.DevServerStartError(error.message);
        }
        throw error;
    }
}
exports.readFileConfig = readFileConfig;
//# sourceMappingURL=readFileConfig.js.map