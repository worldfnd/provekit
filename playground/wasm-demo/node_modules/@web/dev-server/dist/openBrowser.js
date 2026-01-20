"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.openBrowser = void 0;
const open_1 = __importDefault(require("open"));
const path_1 = __importDefault(require("path"));
function isValidURL(str) {
    try {
        return !!new URL(str);
    }
    catch (error) {
        return false;
    }
}
function getBasePath(basePath) {
    if (!basePath) {
        return '';
    }
    if (basePath.endsWith('/')) {
        return basePath.substring(0, basePath.length - 1);
    }
    return basePath;
}
async function openBrowser(config) {
    const basePath = getBasePath(config.basePath);
    let openPath;
    if (typeof config.open === 'string') {
        // user-provided open path
        openPath = config.open === '' ? '/' : config.open;
    }
    else if (config.appIndex) {
        const resolvedAppIndex = path_1.default.resolve(config.appIndex);
        const relativeAppIndex = path_1.default.relative(config.rootDir, resolvedAppIndex);
        const appIndexBrowserPath = `/${relativeAppIndex.split(path_1.default.sep).join('/')}`;
        const appIndexDir = path_1.default.dirname(appIndexBrowserPath);
        // if an appIndex was provided, use it's directory as open path
        openPath = `${basePath}${appIndexDir.endsWith('/') ? appIndexDir : `${appIndexDir}/`}`;
    }
    else {
        openPath = `${basePath}/`;
    }
    if (!isValidURL(openPath)) {
        // construct a full URL to open if the user didn't provide a full URL
        openPath = new URL(openPath, `http${config.http2 ? 's' : ''}://${config.hostname}:${config.port}`).href;
    }
    await (0, open_1.default)(openPath);
}
exports.openBrowser = openBrowser;
//# sourceMappingURL=openBrowser.js.map