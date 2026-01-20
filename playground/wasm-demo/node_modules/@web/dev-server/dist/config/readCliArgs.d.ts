import { DevServerConfig } from './DevServerConfig.js';
export interface DevServerCliArgs extends Partial<Pick<DevServerConfig, 'rootDir' | 'open' | 'appIndex' | 'preserveSymlinks' | 'nodeResolve' | 'watch' | 'esbuildTarget'>> {
    config?: string;
}
export interface ReadCliArgsParams {
    argv?: string[];
}
export declare function readCliArgs({ argv }?: ReadCliArgsParams): DevServerCliArgs;
//# sourceMappingURL=readCliArgs.d.ts.map