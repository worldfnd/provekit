import { DevServerCliArgs } from './readCliArgs.js';
import { DevServerConfig } from './DevServerConfig.js';
export declare function validateConfig(config: Partial<DevServerConfig>): DevServerConfig;
export declare function parseConfig(config: Partial<DevServerConfig>, cliArgs?: DevServerCliArgs): Promise<DevServerConfig>;
//# sourceMappingURL=parseConfig.d.ts.map