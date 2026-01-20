"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getTestProgressReport = void 0;
const test_runner_core_1 = require("@web/test-runner-core");
const nanocolors_1 = require("nanocolors");
const getPassedFailedSkippedCount_js_1 = require("./utils/getPassedFailedSkippedCount.js");
const getCodeCoverage_js_1 = require("./getCodeCoverage.js");
const renderProgressBar_js_1 = require("./renderProgressBar.js");
function getProgressReport(name, minWidth, finishedFiles, activeFiles, testFiles, passedTests, skippedTests, failedTests) {
    const failedText = `${failedTests} failed`;
    const testResults = `${(0, nanocolors_1.green)(`${passedTests} passed`)}` +
        `, ${failedTests !== 0 ? (0, nanocolors_1.red)(failedText) : failedText}` +
        (skippedTests !== 0 ? `, ${(0, nanocolors_1.gray)(`${skippedTests} skipped`)}` : '');
    const progressBar = `${(0, renderProgressBar_js_1.renderProgressBar)(finishedFiles, activeFiles, testFiles)} ${finishedFiles}/${testFiles} test files`;
    return `${`${name}:`.padEnd(minWidth)} ${progressBar} | ${testResults}`;
}
function getTestProgressReport(config, args) {
    const { browsers, browserNames, testRun, sessions, watch, startTime, focusedTestFile, coverage, coverageConfig, testCoverage, } = args;
    const entries = [];
    const unfinishedSessions = Array.from(sessions.forStatusAndTestFile(focusedTestFile, test_runner_core_1.SESSION_STATUS.SCHEDULED, test_runner_core_1.SESSION_STATUS.INITIALIZING, test_runner_core_1.SESSION_STATUS.TEST_STARTED, test_runner_core_1.SESSION_STATUS.TEST_FINISHED));
    const finishedFiles = new Set();
    let failedTestCount = 0;
    let failed = false;
    const longestBrowser = [...browserNames].sort((a, b) => b.length - a.length)[0];
    const minWidth = longestBrowser ? longestBrowser.length + 1 : 0;
    for (const browser of browsers) {
        // when started or not initiliazing we render a progress bar
        const allSessionsForBrowser = Array.from(sessions.forBrowser(browser));
        const sessionsForBrowser = focusedTestFile
            ? allSessionsForBrowser.filter(s => s.testFile === focusedTestFile)
            : allSessionsForBrowser;
        const totalTestFiles = sessionsForBrowser.length;
        let finishedFilesForBrowser = 0;
        let activeFilesForBrowser = 0;
        let passedTestsForBrowser = 0;
        let skippedTestsForBrowser = 0;
        let failedTestsForBrowser = 0;
        for (const session of sessionsForBrowser) {
            if (!session.passed) {
                failed = true;
            }
            if (![test_runner_core_1.SESSION_STATUS.SCHEDULED, test_runner_core_1.SESSION_STATUS.FINISHED].includes(session.status)) {
                activeFilesForBrowser += 1;
            }
            if (session.status === test_runner_core_1.SESSION_STATUS.FINISHED) {
                const { testFile, testResults } = session;
                finishedFiles.add(testFile);
                finishedFilesForBrowser += 1;
                if (testResults) {
                    const parsed = (0, getPassedFailedSkippedCount_js_1.getPassedFailedSkippedCount)(testResults);
                    passedTestsForBrowser += parsed.passed;
                    skippedTestsForBrowser += parsed.skipped;
                    failedTestsForBrowser += parsed.failed;
                    failedTestCount += parsed.failed;
                }
            }
        }
        entries.push(getProgressReport(browser.name, minWidth, finishedFilesForBrowser, activeFilesForBrowser, totalTestFiles, passedTestsForBrowser, skippedTestsForBrowser, failedTestsForBrowser));
    }
    entries.push('');
    if (coverage && coverageConfig) {
        if (testCoverage) {
            if (!testCoverage.passed) {
                failed = true;
            }
            const coverageReport = (0, getCodeCoverage_js_1.getCodeCoverage)(testCoverage, watch, coverageConfig);
            entries.push(...coverageReport);
        }
    }
    if (testRun !== -1 && unfinishedSessions.length === 0) {
        if (coverage && !testCoverage) {
            entries.push((0, nanocolors_1.bold)('Calculating code coverage...'));
        }
        else if (config.watch) {
            entries.push((0, nanocolors_1.bold)(`Finished running tests, watching for file changes...`));
        }
        else {
            const durationInSec = (Date.now() - startTime) / 1000;
            const duration = Math.trunc(durationInSec * 10) / 10;
            if (failed) {
                if (coverage && !(testCoverage === null || testCoverage === void 0 ? void 0 : testCoverage.passed)) {
                    entries.push((0, nanocolors_1.bold)((0, nanocolors_1.red)(`Finished running tests in ${duration}s, failed to meet coverage threshold.`)));
                }
                else if (failedTestCount > 0) {
                    entries.push((0, nanocolors_1.bold)((0, nanocolors_1.red)(`Finished running tests in ${duration}s with ${failedTestCount} failed tests.`)));
                }
                else if (finishedFiles.size > 0) {
                    entries.push((0, nanocolors_1.bold)((0, nanocolors_1.red)(`Error while running tests.`)));
                }
                else {
                    entries.push((0, nanocolors_1.bold)((0, nanocolors_1.red)(`Failed to run any tests.`)));
                }
            }
            else {
                entries.push((0, nanocolors_1.bold)(`Finished running tests in ${duration}s, all tests passed! 🎉`));
            }
        }
    }
    else {
        entries.push((0, nanocolors_1.bold)('Running tests...'));
    }
    entries.push('');
    return entries;
}
exports.getTestProgressReport = getTestProgressReport;
//# sourceMappingURL=getTestProgress.js.map