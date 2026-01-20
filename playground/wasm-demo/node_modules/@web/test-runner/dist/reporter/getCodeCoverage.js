"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getCodeCoverage = void 0;
const path_1 = __importDefault(require("path"));
const nanocolors_1 = require("nanocolors");
const coverageTypes = [
    'lines',
    'statements',
    'branches',
    'functions',
];
function getCodeCoverage(testCoverage, watch, coverageConfig) {
    var _a, _b;
    const entries = [];
    const coverageSum = coverageTypes.reduce((all, type) => all + testCoverage.summary[type].pct, 0);
    const avgCoverage = Math.round((coverageSum * 100) / 4) / 100;
    if (!Number.isNaN(avgCoverage)) {
        const percent = `${avgCoverage} %`;
        entries.push(`Code coverage: ${(0, nanocolors_1.bold)(testCoverage.passed ? (0, nanocolors_1.green)(percent) : (0, nanocolors_1.red)(percent))}`);
    }
    if (!testCoverage.passed && coverageConfig.threshold) {
        coverageTypes.forEach(type => {
            if (testCoverage.summary[type].pct < coverageConfig.threshold[type]) {
                entries.push(`Coverage for ${(0, nanocolors_1.bold)(type)} failed with ${(0, nanocolors_1.bold)((0, nanocolors_1.red)(`${testCoverage.summary[type].pct} %`))} compared to configured ${(0, nanocolors_1.bold)(`${coverageConfig.threshold[type]} %`)}`);
            }
        });
    }
    if (!watch && coverageConfig.report && ((_a = coverageConfig.reporters) === null || _a === void 0 ? void 0 : _a.includes('lcov'))) {
        entries.push(`View full coverage report at ${(0, nanocolors_1.underline)(path_1.default.join((_b = coverageConfig.reportDir) !== null && _b !== void 0 ? _b : '', 'lcov-report', 'index.html'))}`);
    }
    entries.push('');
    return entries;
}
exports.getCodeCoverage = getCodeCoverage;
//# sourceMappingURL=getCodeCoverage.js.map