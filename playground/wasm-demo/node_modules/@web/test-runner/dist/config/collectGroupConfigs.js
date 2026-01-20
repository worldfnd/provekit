"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.collectGroupConfigs = void 0;
const config_loader_1 = require("@web/config-loader");
const globby_1 = __importDefault(require("globby"));
const TestRunnerStartError_js_1 = require("../TestRunnerStartError.js");
function validateGroupConfig(configFilePath, config) {
    if (config.browsers != null && !Array.isArray(config.browsers)) {
        throw new TestRunnerStartError_js_1.TestRunnerStartError(`Group config at ${configFilePath} has invalid browsers option. It should be an array.`);
    }
    if (config.files != null && !(typeof config.files === 'string' || Array.isArray(config.files))) {
        throw new TestRunnerStartError_js_1.TestRunnerStartError(`Group config at ${configFilePath} has an invalid files option. It should be a string or an array.`);
    }
    return Object.assign({ name: configFilePath, configFilePath }, config);
}
async function collectGroupConfigs(patterns) {
    const groupConfigFiles = new Set();
    const groupConfigs = [];
    for (const pattern of patterns) {
        const filePaths = globby_1.default.sync(pattern, { absolute: true });
        for (const filePath of filePaths) {
            groupConfigFiles.add(filePath);
        }
    }
    for (const groupConfigFile of groupConfigFiles) {
        try {
            const maybeGroupConfig = (await (0, config_loader_1.readConfig)('', groupConfigFile));
            const groupConfig = validateGroupConfig(groupConfigFile, maybeGroupConfig);
            groupConfigs.push(groupConfig);
        }
        catch (error) {
            if (error instanceof config_loader_1.ConfigLoaderError) {
                throw new TestRunnerStartError_js_1.TestRunnerStartError(error.message);
            }
            throw error;
        }
    }
    return groupConfigs;
}
exports.collectGroupConfigs = collectGroupConfigs;
//# sourceMappingURL=collectGroupConfigs.js.map