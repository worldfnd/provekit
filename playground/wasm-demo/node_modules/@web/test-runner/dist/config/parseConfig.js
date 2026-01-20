"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseConfig = exports.validateConfig = void 0;
const test_runner_chrome_1 = require("@web/test-runner-chrome");
const plugins_1 = require("@web/test-runner-commands/plugins");
const portfinder_1 = require("portfinder");
const path_1 = __importDefault(require("path"));
const os_1 = require("os");
const mergeConfigs_js_1 = require("./mergeConfigs.js");
const dev_server_1 = require("@web/dev-server");
const TestRunnerStartError_js_1 = require("../TestRunnerStartError.js");
const collectGroupConfigs_js_1 = require("./collectGroupConfigs.js");
const loadLauncher_js_1 = require("./loadLauncher.js");
const defaultReporter_js_1 = require("../reporter/defaultReporter.js");
const TestRunnerLogger_js_1 = require("../logger/TestRunnerLogger.js");
const secondMs = 1000;
const minuteMs = secondMs * 60;
const defaultConfig = {
    rootDir: process.cwd(),
    protocol: 'http:',
    hostname: 'localhost',
    middleware: [],
    plugins: [],
    watch: false,
    concurrentBrowsers: 2,
    concurrency: Math.max(1, (0, os_1.cpus)().length / 2),
    browserStartTimeout: minuteMs / 2,
    testsStartTimeout: secondMs * 20,
    testsFinishTimeout: minuteMs * 2,
    browserLogs: true,
};
const defaultCoverageConfig = {
    exclude: ['**/node_modules/**/*', '**/web_modules/**/*'],
    threshold: { statements: 0, functions: 0, branches: 0, lines: 0 },
    report: true,
    reportDir: 'coverage',
    reporters: ['lcov'],
};
function validate(config, key, type) {
    if (config[key] == null) {
        return;
    }
    if (typeof config[key] !== type) {
        throw new TestRunnerStartError_js_1.TestRunnerStartError(`Configuration error: The ${key} setting should be a ${type}.`);
    }
}
const stringSettings = ['rootDir', 'hostname'];
const numberSettings = [
    'port',
    'concurrentBrowsers',
    'concurrency',
    'browserStartTimeout',
    'testsStartTimeout',
    'testsFinishTimeout',
];
const booleanSettings = [
    'watch',
    'preserveSymlinks',
    'browserLogs',
    'coverage',
    'staticLogging',
    'manual',
    'open',
    'debug',
];
function validateConfig(config) {
    stringSettings.forEach(key => validate(config, key, 'string'));
    numberSettings.forEach(key => validate(config, key, 'number'));
    booleanSettings.forEach(key => validate(config, key, 'boolean'));
    if (config.esbuildTarget != null &&
        !(typeof config.esbuildTarget === 'string' || Array.isArray(config.esbuildTarget))) {
        throw new TestRunnerStartError_js_1.TestRunnerStartError(`Configuration error: The esbuildTarget setting should be a string or array.`);
    }
    if (config.files != null && !(typeof config.files === 'string' || Array.isArray(config.files))) {
        throw new TestRunnerStartError_js_1.TestRunnerStartError(`Configuration error: The files setting should be a string or an array.`);
    }
    return config;
}
exports.validateConfig = validateConfig;
async function parseConfigGroups(config, cliArgs) {
    const groupConfigs = [];
    const configPatterns = [];
    if (cliArgs.groups) {
        // groups are provided from CLI args
        configPatterns.push(cliArgs.groups);
    }
    else if (config.groups) {
        // groups are provided from config
        for (const entry of config.groups) {
            if (typeof entry === 'object') {
                groupConfigs.push(entry);
            }
            else {
                configPatterns.push(entry);
            }
        }
    }
    // group entries which are strings are globs which point to group conigs
    groupConfigs.push(...(await (0, collectGroupConfigs_js_1.collectGroupConfigs)(configPatterns)));
    return groupConfigs;
}
async function parseConfig(config, cliArgs = {}) {
    var _a, _b;
    const cliArgsConfig = Object.assign({}, cliArgs);
    // CLI has properties with the same name as the config, but with different values
    // delete them so they don't overwrite when merging, the CLI values are read separately
    delete cliArgsConfig.groups;
    delete cliArgsConfig.browsers;
    const mergedConfigs = (0, mergeConfigs_js_1.mergeConfigs)(defaultConfig, config, cliArgsConfig);
    // backwards compatibility for configs written for es-dev-server, where middleware was
    // spelled incorrectly as middlewares
    if (Array.isArray(mergedConfigs.middlewares)) {
        mergedConfigs.middleware.push(...mergedConfigs.middlewares);
    }
    const finalConfig = validateConfig(mergedConfigs);
    // filter out non-objects from plugin list
    finalConfig.plugins = ((_a = finalConfig.plugins) !== null && _a !== void 0 ? _a : []).filter(pl => typeof pl === 'object');
    // ensure rootDir is always resolved
    if (typeof finalConfig.rootDir === 'string') {
        finalConfig.rootDir = path_1.default.resolve(finalConfig.rootDir);
    }
    else {
        throw new TestRunnerStartError_js_1.TestRunnerStartError('No rootDir specified.');
    }
    // generate a default random port
    if (typeof finalConfig.port !== 'number') {
        finalConfig.port = await (0, portfinder_1.getPortPromise)({ port: 8000 });
    }
    finalConfig.coverageConfig = Object.assign(Object.assign({}, defaultCoverageConfig), finalConfig.coverageConfig);
    let groupConfigs = await parseConfigGroups(finalConfig, cliArgs);
    if (groupConfigs.find(g => g.name === 'default')) {
        throw new TestRunnerStartError_js_1.TestRunnerStartError('Cannot create a group named "default". This named is reserved by the test runner.');
    }
    if (cliArgs.group != null) {
        if (cliArgs.group === 'default') {
            // default group is an alias for the root config
            groupConfigs = [];
        }
        else {
            const groupConfig = groupConfigs.find(c => c.name === cliArgs.group);
            if (!groupConfig) {
                throw new TestRunnerStartError_js_1.TestRunnerStartError(`Could not find any group named ${cliArgs.group}`);
            }
            // when focusing a group, ensure that the "default" group isn't run
            // we can improve this by relying only on groups inside the test runner itself
            if (groupConfig.files == null) {
                groupConfig.files = finalConfig.files;
            }
            finalConfig.files = undefined;
            groupConfigs = [groupConfig];
        }
    }
    if (cliArgs.puppeteer) {
        if (finalConfig.browsers && finalConfig.browsers.length > 0) {
            throw new TestRunnerStartError_js_1.TestRunnerStartError('The --puppeteer flag cannot be used when defining browsers manually in your finalConfig.');
        }
        finalConfig.browsers = (0, loadLauncher_js_1.puppeteerLauncher)(cliArgs.browsers);
    }
    else if (cliArgs.playwright) {
        if (finalConfig.browsers && finalConfig.browsers.length > 0) {
            throw new TestRunnerStartError_js_1.TestRunnerStartError('The --playwright flag cannot be used when defining browsers manually in your finalConfig.');
        }
        finalConfig.browsers = (0, loadLauncher_js_1.playwrightLauncher)(cliArgs.browsers);
    }
    else {
        if (cliArgs.browsers != null) {
            throw new TestRunnerStartError_js_1.TestRunnerStartError(`The browsers option must be used along with the puppeteer or playwright option.`);
        }
        // add default chrome launcher if the user did not configure their own browsers
        if (!finalConfig.browsers) {
            finalConfig.browsers = [(0, test_runner_chrome_1.chromeLauncher)()];
        }
    }
    finalConfig.testFramework = Object.assign({ path: require.resolve('@web/test-runner-mocha/dist/autorun.js') }, ((_b = finalConfig.testFramework) !== null && _b !== void 0 ? _b : {}));
    if (!finalConfig.reporters) {
        finalConfig.reporters = [(0, defaultReporter_js_1.defaultReporter)()];
    }
    if (!finalConfig.logger) {
        finalConfig.logger = new TestRunnerLogger_js_1.TestRunnerLogger(config.debug);
    }
    if (finalConfig.plugins == null) {
        finalConfig.plugins = [];
    }
    // plugin with a noop transformImport hook, this will cause the dev server to analyze modules and
    // catch syntax errors. this way we still report syntax errors when the user has no flags enabled
    finalConfig.plugins.unshift({
        name: 'syntax-checker',
        transformImport() {
            return undefined;
        },
    });
    finalConfig.plugins.unshift((0, plugins_1.setViewportPlugin)(), (0, plugins_1.emulateMediaPlugin)(), (0, plugins_1.setUserAgentPlugin)(), (0, plugins_1.selectOptionPlugin)(), (0, plugins_1.filePlugin)(), (0, plugins_1.sendKeysPlugin)(), (0, plugins_1.sendMousePlugin)(), (0, plugins_1.snapshotPlugin)({ updateSnapshots: !!cliArgs.updateSnapshots }));
    if (finalConfig.nodeResolve) {
        const userOptions = typeof finalConfig.nodeResolve === 'object' ? finalConfig.nodeResolve : undefined;
        // do node resolve after user plugins, to allow user plugins to resolve imports
        finalConfig.plugins.push((0, dev_server_1.nodeResolvePlugin)(finalConfig.rootDir, finalConfig.preserveSymlinks, userOptions));
    }
    if (finalConfig === null || finalConfig === void 0 ? void 0 : finalConfig.esbuildTarget) {
        finalConfig.plugins.unshift((0, dev_server_1.esbuildPlugin)(finalConfig.esbuildTarget));
    }
    if ((!finalConfig.files || finalConfig.files.length === 0) && groupConfigs.length === 0) {
        throw new TestRunnerStartError_js_1.TestRunnerStartError('Did not find any tests to run. Use the "files" or "groups" option to configure test files.');
    }
    return { config: finalConfig, groupConfigs };
}
exports.parseConfig = parseConfig;
//# sourceMappingURL=parseConfig.js.map