"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.esbuildPlugin = void 0;
function requirePlugin() {
    try {
        const path = require.resolve('@web/dev-server-esbuild', { paths: [__dirname, process.cwd()] });
        return require(path);
    }
    catch (error) {
        if (error.code === 'MODULE_NOT_FOUND') {
            throw new Error('You need to add @web/dev-server-esbuild as a dependency of your project to use the esbuild flags.');
        }
        else {
            throw error;
        }
    }
}
function esbuildPlugin(target) {
    const pluginModule = requirePlugin();
    return pluginModule.esbuildPlugin({ target });
}
exports.esbuildPlugin = esbuildPlugin;
//# sourceMappingURL=esbuildPlugin.js.map