"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportTestFileErrors = void 0;
const nanocolors_1 = require("nanocolors");
const getFailedOnBrowsers_js_1 = require("./utils/getFailedOnBrowsers.js");
function isSameError(a, b) {
    return a.message === b.message && a.stack === b.stack;
}
function reportTestFileErrors(logger, browserNames, favoriteBrowser, sessionsForTestFile, logFileNames) {
    const reports = [];
    for (const session of sessionsForTestFile) {
        for (const error of session.errors) {
            let report = reports.find(r => isSameError(r.error, error));
            if (!report) {
                report = {
                    testFile: session.testFile,
                    failedBrowsers: [],
                    error,
                };
                reports.push(report);
            }
            report.failedBrowsers.push(session.browser.name);
            if (session.browser.name === favoriteBrowser) {
                report.error = error;
            }
        }
    }
    for (const report of reports) {
        const { name, message = 'Unknown error' } = report.error;
        const errorMsg = name ? `${name}: ${message}` : message;
        const failedOn = (0, getFailedOnBrowsers_js_1.getFailedOnBrowsers)(browserNames, report.failedBrowsers);
        if (report.error.stack) {
            // there was a stack trace, take the first line and decorate it with an icon and which browsers it failed on
            logger.log(` ❌ ${(0, nanocolors_1.red)(errorMsg)} ${failedOn}`);
            // if there was more to the stack trace, print it
            logger.group();
            logger.group();
            logger.log((0, nanocolors_1.gray)(report.error.stack));
            logger.groupEnd();
            logger.groupEnd();
        }
        else {
            // there was no stack trace, so just print the error message
            logger.log(` ❌ ${errorMsg} ${failedOn}`);
        }
        if (logFileNames) {
            logger.log(`  ${report.testFile}`);
        }
        logger.log('');
    }
}
exports.reportTestFileErrors = reportTestFileErrors;
//# sourceMappingURL=reportTestFileErrors.js.map