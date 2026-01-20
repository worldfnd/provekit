"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mergeConfigs = void 0;
const arrayKeys = ['plugins', 'middleware'];
function mergeConfigs(...configs) {
    const finalConfig = {
        plugins: [],
        middleware: [],
    };
    for (const config of configs) {
        if (config) {
            for (const [key, value] of Object.entries(config)) {
                if (arrayKeys.includes(key)) {
                    if (Array.isArray(value)) {
                        finalConfig[key].push(...value);
                    }
                }
                else {
                    finalConfig[key] = value;
                }
            }
        }
    }
    return finalConfig;
}
exports.mergeConfigs = mergeConfigs;
//# sourceMappingURL=mergeConfigs.js.map