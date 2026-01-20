import { TestRunnerConfig } from './TestRunnerConfig.js';
export interface TestRunnerCliArgs extends Partial<Pick<TestRunnerConfig, 'files' | 'rootDir' | 'watch' | 'coverage' | 'concurrentBrowsers' | 'concurrency' | 'staticLogging' | 'manual' | 'open' | 'port' | 'preserveSymlinks' | 'nodeResolve' | 'debug' | 'esbuildTarget'>> {
    config?: string;
    groups?: string;
    group?: string;
    puppeteer?: boolean;
    playwright?: boolean;
    browsers?: string[];
    updateSnapshots?: boolean;
}
export interface ReadCliArgsParams {
    argv?: string[];
}
export declare function readCliArgs({ argv }?: ReadCliArgsParams): TestRunnerCliArgs;
//# sourceMappingURL=readCliArgs.d.ts.map