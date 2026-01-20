"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportTestFileResults = void 0;
const nanocolors_1 = require("nanocolors");
const path_1 = require("path");
const reportTestsErrors_js_1 = require("./reportTestsErrors.js");
const reportBrowserLogs_js_1 = require("./reportBrowserLogs.js");
const reportRequest404s_js_1 = require("./reportRequest404s.js");
const reportTestFileErrors_js_1 = require("./reportTestFileErrors.js");
function reportTestFileResults(logger, testFile, allBrowserNames, favoriteBrowser, sessionsForTestFile) {
    const failedSessions = sessionsForTestFile.filter(s => !s.passed);
    (0, reportBrowserLogs_js_1.reportBrowserLogs)(logger, sessionsForTestFile);
    (0, reportRequest404s_js_1.reportRequest404s)(logger, sessionsForTestFile);
    (0, reportTestFileErrors_js_1.reportTestFileErrors)(logger, allBrowserNames, favoriteBrowser, sessionsForTestFile);
    if (failedSessions.length > 0) {
        (0, reportTestsErrors_js_1.reportTestsErrors)(logger, allBrowserNames, favoriteBrowser, failedSessions);
    }
    if (logger.buffer.length > 0) {
        logger.buffer.unshift({
            method: 'log',
            args: [`${(0, nanocolors_1.bold)((0, nanocolors_1.cyan)((0, path_1.relative)(process.cwd(), testFile)))}:\n`],
        });
    }
}
exports.reportTestFileResults = reportTestFileResults;
//# sourceMappingURL=reportTestFileResults.js.map