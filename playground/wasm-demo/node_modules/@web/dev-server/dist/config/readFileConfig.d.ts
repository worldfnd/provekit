export interface ReadFileConfigParams {
    /**
     * The config name to use. Defaults to web-dev-server.config.{mjs,cjs,js}
     */
    configName?: string;
    /**
     * Path to the config file. If this is not set, the config is looked up in the
     * current working directory using the config name.
     */
    configPath?: string;
}
/**
 * Reads the config from disk, defaults to process.cwd() + web-dev-server.config.{mjs,js,cjs} or
 * a custom config path.
 * @param customConfig the custom location to read the config from
 */
export declare function readFileConfig({ configName, configPath, }?: ReadFileConfigParams): Promise<any>;
//# sourceMappingURL=readFileConfig.d.ts.map