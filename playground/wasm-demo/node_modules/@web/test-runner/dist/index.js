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
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatError = exports.dotReporter = exports.summaryReporter = exports.defaultReporter = exports.startTestRunner = exports.chromeLauncher = void 0;
__exportStar(require("@web/test-runner-core"), exports);
var test_runner_chrome_1 = require("@web/test-runner-chrome");
Object.defineProperty(exports, "chromeLauncher", { enumerable: true, get: function () { return test_runner_chrome_1.chromeLauncher; } });
var startTestRunner_js_1 = require("./startTestRunner.js");
Object.defineProperty(exports, "startTestRunner", { enumerable: true, get: function () { return startTestRunner_js_1.startTestRunner; } });
var defaultReporter_js_1 = require("./reporter/defaultReporter.js");
Object.defineProperty(exports, "defaultReporter", { enumerable: true, get: function () { return defaultReporter_js_1.defaultReporter; } });
var summaryReporter_js_1 = require("./reporter/summaryReporter.js");
Object.defineProperty(exports, "summaryReporter", { enumerable: true, get: function () { return summaryReporter_js_1.summaryReporter; } });
var dotReporter_js_1 = require("./reporter/dotReporter.js");
Object.defineProperty(exports, "dotReporter", { enumerable: true, get: function () { return dotReporter_js_1.dotReporter; } });
var reportTestsErrors_js_1 = require("./reporter/reportTestsErrors.js");
Object.defineProperty(exports, "formatError", { enumerable: true, get: function () { return reportTestsErrors_js_1.formatError; } });
//# sourceMappingURL=index.js.map