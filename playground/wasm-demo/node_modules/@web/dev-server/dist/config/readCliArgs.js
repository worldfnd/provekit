"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.readCliArgs = void 0;
const command_line_args_1 = __importDefault(require("command-line-args"));
const command_line_usage_1 = __importDefault(require("command-line-usage"));
const camelcase_1 = __importDefault(require("camelcase"));
const options = [
    {
        name: 'config',
        alias: 'c',
        type: String,
        description: 'The file to read configuration from. Config entries are camelCases flags.',
    },
    {
        name: 'root-dir',
        alias: 'r',
        type: String,
        description: 'The root directory to serve files from. Defaults to the current working directory.',
    },
    {
        name: 'base-path',
        alias: 'b',
        type: String,
        description: 'Prefix to strip from requests URLs.',
    },
    {
        name: 'open',
        alias: 'o',
        type: String,
        description: 'Opens the browser on app-index, root dir or a custom path.',
    },
    {
        name: 'app-index',
        alias: 'a',
        type: String,
        description: "The app's index.html file. When set, serves the index.html for non-file requests. Use this to enable SPA routing.",
    },
    {
        name: 'preserve-symlinks',
        description: "Don't follow symlinks when resolving module imports.",
        type: Boolean,
    },
    {
        name: 'node-resolve',
        description: 'Resolve bare module imports using node resolution',
        type: Boolean,
    },
    {
        name: 'watch',
        alias: 'w',
        description: 'Reload the browser when files are changed.',
        type: Boolean,
    },
    {
        name: 'port',
        alias: 'p',
        description: 'Port to bind the server to.',
        type: Number,
    },
    {
        name: 'hostname',
        alias: 'h',
        description: 'Hostname to bind the server to.',
    },
    {
        name: 'esbuild-target',
        type: String,
        multiple: true,
        description: 'JS language target to compile down to using esbuild. Recommended value is "auto", which compiles based on user agent. Check the docs for more options.',
    },
    {
        name: 'debug',
        type: Boolean,
        description: 'Whether to log debug messages.',
    },
    {
        name: 'help',
        type: Boolean,
        description: 'List all possible commands.',
    },
];
function readCliArgs({ argv = process.argv } = {}) {
    const cliArgs = (0, command_line_args_1.default)(options, { argv, partial: true });
    // when the open flag is used without arguments, it defaults to null. treat this as "true"
    if ('open' in cliArgs && typeof cliArgs.open !== 'string') {
        cliArgs.open = true;
    }
    if ('help' in cliArgs) {
        /* eslint-disable-next-line no-console */
        console.log((0, command_line_usage_1.default)([
            {
                header: 'Web Dev Server',
                content: 'Dev Server for web development.',
            },
            {
                header: 'Usage',
                content: 'web-dev-server [options...]' + '\nwds [options...]',
            },
            { header: 'Options', optionList: options },
        ]));
        process.exit();
    }
    const cliArgsConfig = {};
    for (const [key, value] of Object.entries(cliArgs)) {
        cliArgsConfig[(0, camelcase_1.default)(key)] = value;
    }
    return cliArgsConfig;
}
exports.readCliArgs = readCliArgs;
//# sourceMappingURL=readCliArgs.js.map