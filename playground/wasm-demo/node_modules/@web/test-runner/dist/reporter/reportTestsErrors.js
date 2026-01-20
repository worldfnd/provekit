"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportTestsErrors = exports.formatError = void 0;
const nanocolors_1 = require("nanocolors");
const diff = __importStar(require("diff"));
const getFailedOnBrowsers_js_1 = require("./utils/getFailedOnBrowsers.js");
const getFlattenedTestResults_js_1 = require("./utils/getFlattenedTestResults.js");
function renderDiff(actual, expected) {
    function cleanUp(line) {
        if (line[0] === '+') {
            return (0, nanocolors_1.green)(line);
        }
        if (line[0] === '-') {
            return (0, nanocolors_1.red)(line);
        }
        if (line.match(/@@/)) {
            return null;
        }
        if (line.match(/\\ No newline/)) {
            return null;
        }
        return line;
    }
    const diffMsg = diff
        .createPatch('string', actual, expected)
        .split('\n')
        .splice(4)
        .map(cleanUp)
        .filter(l => !!l)
        .join('\n');
    return `${(0, nanocolors_1.green)('+ expected')} ${(0, nanocolors_1.red)('- actual')}\n\n${diffMsg}`;
}
function formatError(error) {
    const strings = [];
    const { name, message = 'Unknown error' } = error;
    const errorMsg = name ? `${name}: ${message}` : message;
    const showDiff = typeof error.expected === 'string' && typeof error.actual === 'string';
    strings.push((0, nanocolors_1.red)(errorMsg));
    if (showDiff) {
        strings.push(`${renderDiff(error.actual, error.expected)}\n`);
    }
    if (error.stack) {
        if (showDiff) {
            const dedented = error.stack
                .split('\n')
                .map(s => s.trim())
                .join('\n');
            strings.push((0, nanocolors_1.gray)(dedented));
        }
        else {
            strings.push((0, nanocolors_1.gray)(error.stack));
        }
    }
    if (!error.expected && !error.stack) {
        strings.push((0, nanocolors_1.red)(error.message || 'Unknown error'));
    }
    return strings.join('\n');
}
exports.formatError = formatError;
function reportTestsErrors(logger, allBrowserNames, favoriteBrowser, failedSessions) {
    var _a;
    const testErrorsPerBrowser = new Map();
    for (const session of failedSessions) {
        if (session.testResults) {
            const flattenedTests = (0, getFlattenedTestResults_js_1.getFlattenedTestResults)(session.testResults);
            for (const test of flattenedTests) {
                if (test.error) {
                    let testErrorsForBrowser = testErrorsPerBrowser.get(test.name);
                    if (!testErrorsForBrowser) {
                        testErrorsForBrowser = new Map();
                        testErrorsPerBrowser.set(test.name, testErrorsForBrowser);
                    }
                    if (test.error) {
                        testErrorsForBrowser.set(session.browser.name, test.error);
                    }
                }
            }
        }
    }
    if (testErrorsPerBrowser.size > 0) {
        for (const [name, errorsForBrowser] of testErrorsPerBrowser) {
            const failedBrowsers = Array.from(errorsForBrowser.keys());
            const error = (_a = errorsForBrowser.get(favoriteBrowser)) !== null && _a !== void 0 ? _a : errorsForBrowser.get(failedBrowsers[0]);
            const failedOn = (0, getFailedOnBrowsers_js_1.getFailedOnBrowsers)(allBrowserNames, failedBrowsers);
            logger.log(` ❌ ${name}${failedOn}`);
            logger.group();
            logger.group();
            logger.group();
            logger.log(formatError(error));
            logger.groupEnd();
            logger.groupEnd();
            logger.groupEnd();
            logger.log('');
        }
    }
}
exports.reportTestsErrors = reportTestsErrors;
//# sourceMappingURL=reportTestsErrors.js.map