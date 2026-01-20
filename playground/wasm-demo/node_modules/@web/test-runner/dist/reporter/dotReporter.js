"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.dotReporter = void 0;
const reportTestsErrors_js_1 = require("./reportTestsErrors.js");
const reportTestFileErrors_js_1 = require("./reportTestFileErrors.js");
const TestRunnerLogger_js_1 = require("../logger/TestRunnerLogger.js");
const color = ([x, y]) => (z) => `\x1b[${x}m${z}\x1b[${y}m${reset}`;
const reset = `\x1b[0m\x1b[0m`;
const red = color([31, 89]);
/** Test reporter that summarizes all test for a given run using dot notation */
function dotReporter() {
    let args;
    let favoriteBrowser;
    const logger = new TestRunnerLogger_js_1.TestRunnerLogger();
    function log(passed) {
        logger.log(passed ? '.' : red('x'));
    }
    function logResults(results) {
        var _a, _b;
        for (const result of (_a = results === null || results === void 0 ? void 0 : results.tests) !== null && _a !== void 0 ? _a : []) {
            log(result.passed);
        }
        for (const suite of (_b = results === null || results === void 0 ? void 0 : results.suites) !== null && _b !== void 0 ? _b : []) {
            logSuite(suite);
        }
    }
    function logSuite(suite) {
        logResults(suite);
    }
    return {
        start(_args) {
            var _a;
            args = _args;
            favoriteBrowser =
                (_a = args.browserNames.find(name => {
                    const n = name.toLowerCase();
                    return n.includes('chrome') || n.includes('chromium') || n.includes('firefox');
                })) !== null && _a !== void 0 ? _a : args.browserNames[0];
        },
        reportTestFileResults({ sessionsForTestFile: sessions }) {
            for (const session of sessions) {
                logResults(session.testResults);
            }
        },
        onTestRunFinished({ sessions }) {
            const failedSessions = sessions.filter(s => !s.passed);
            if (failedSessions.length > 0) {
                logger.log('\n\nErrors Reported in Tests:\n\n');
                (0, reportTestsErrors_js_1.reportTestsErrors)(logger, args.browserNames, favoriteBrowser, failedSessions);
                (0, reportTestFileErrors_js_1.reportTestFileErrors)(logger, args.browserNames, favoriteBrowser, failedSessions, true);
            }
        },
    };
}
exports.dotReporter = dotReporter;
//# sourceMappingURL=dotReporter.js.map