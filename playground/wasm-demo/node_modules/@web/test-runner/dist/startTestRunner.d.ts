import { TestRunner } from '@web/test-runner-core';
import { TestRunnerConfig } from './config/TestRunnerConfig.js';
export interface StartTestRunnerParams {
    /**
     * Optional config to merge with the user-defined config.
     */
    config?: Partial<TestRunnerConfig>;
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
     * Array to read the CLI args from. Defaults to process.argv.
     */
    argv?: string[];
}
/**
 * Starts the test runner.
 */
export declare function startTestRunner(options?: StartTestRunnerParams): Promise<TestRunner | undefined>;
//# sourceMappingURL=startTestRunner.d.ts.map