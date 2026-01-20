"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.playwrightLauncher = exports.puppeteerLauncher = void 0;
const TestRunnerStartError_js_1 = require("../TestRunnerStartError.js");
/* eslint-disable @typescript-eslint/no-var-requires */
const puppeteerBrowsers = ['chrome', 'firefox'];
const playwrightBrowsers = ['chromium', 'firefox', 'webkit'];
function loadLauncher(name) {
    const pkg = `@web/test-runner-${name}`;
    try {
        const path = require.resolve(pkg, { paths: [__dirname, process.cwd()] });
        return require(path);
    }
    catch (error) {
        if (error.code === 'MODULE_NOT_FOUND') {
            throw new TestRunnerStartError_js_1.TestRunnerStartError(`You need to add ${pkg} as a dependency of your project to use the --${name} flag.`);
        }
        else {
            throw error;
        }
    }
}
function puppeteerLauncher(browsers = ['chrome']) {
    for (const browser of browsers) {
        if (!puppeteerBrowsers.includes(browser)) {
            throw new TestRunnerStartError_js_1.TestRunnerStartError(`Unknown puppeteer browser: ${browser}. ` +
                `Supported browsers: ${puppeteerBrowsers.join(', ')}`);
        }
    }
    const launcher = loadLauncher('puppeteer').puppeteerLauncher;
    return browsers.map(product => launcher({ launchOptions: { product } }));
}
exports.puppeteerLauncher = puppeteerLauncher;
function playwrightLauncher(browsers = ['chromium']) {
    for (const browser of browsers) {
        if (!playwrightBrowsers.includes(browser)) {
            throw new TestRunnerStartError_js_1.TestRunnerStartError(`Unknown playwright browser: ${browser}. ` +
                `Supported browsers: ${playwrightBrowsers.join(', ')}`);
        }
    }
    const launcher = loadLauncher('playwright').playwrightLauncher;
    return browsers.map(product => launcher({ product }));
}
exports.playwrightLauncher = playwrightLauncher;
//# sourceMappingURL=loadLauncher.js.map