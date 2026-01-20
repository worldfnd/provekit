import { TestRunnerCoreConfig, TestRunnerGroupConfig } from '@web/test-runner-core';
import { TestRunnerCliArgs } from './readCliArgs.js';
import { TestRunnerConfig } from './TestRunnerConfig.js';
export declare function validateConfig(config: Partial<TestRunnerConfig>): TestRunnerConfig;
export declare function parseConfig(config: Partial<TestRunnerConfig>, cliArgs?: TestRunnerCliArgs): Promise<{
    config: TestRunnerCoreConfig;
    groupConfigs: TestRunnerGroupConfig[];
}>;
//# sourceMappingURL=parseConfig.d.ts.map