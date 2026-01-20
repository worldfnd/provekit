"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.watchPlugin = void 0;
const debounce_1 = __importDefault(require("debounce"));
function watchPlugin() {
    return {
        name: 'watch',
        injectWebSocket: true,
        serverStart({ fileWatcher, webSockets }) {
            if (!webSockets) {
                throw new Error('Cannot use watch mode when web sockets are disabled.');
            }
            function onFileChanged() {
                webSockets.sendImport('data:text/javascript,window.location.reload()');
            }
            const onChange = (0, debounce_1.default)(onFileChanged, 100);
            fileWatcher.addListener('change', onChange);
            fileWatcher.addListener('unlink', onChange);
        },
    };
}
exports.watchPlugin = watchPlugin;
//# sourceMappingURL=watchPlugin.js.map