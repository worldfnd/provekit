import { DevServer } from '@web/dev-server-core';
import { DevServerConfig } from './config/DevServerConfig.js';
export interface StartDevServerParams {
    /**
     * Optional config to merge with the user-defined config.
     */
    config?: Partial<DevServerConfig>;
    /**
     * Whether to read CLI args. Default true.
     */
    readCliArgs?: boolean;
    /**
     * Whether to read a user config from the file system. Default true.
     */
    readFileConfig?: boolean;
    /**
     * Name of the configuration to read. Defaults to web-dev-server.config.{mjs,cjs,js}
     */
    configName?: string;
    /**
     * Whether to automatically exit the process when the server is stopped, killed or an error is thrown.
     */
    autoExitProcess?: boolean;
    /**
     * Whether to log a message when the server is started.
     */
    logStartMessage?: boolean;
    /**
     * Array to read the CLI args from. Defaults to process.argv.
     */
    argv?: string[];
}
/**
 * Starts the dev server.
 */
export declare function startDevServer(options?: StartDevServerParams): Promise<DevServer>;
//# sourceMappingURL=startDevServer.d.ts.map