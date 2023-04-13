export interface ServerConfig {
    id: string;
    addr: string;
    port: number;
    localUrl: string;
    publicUrl: string;
}
export declare let serverConfig: ServerConfig;
export declare function updateServerConfig(vars: Partial<ServerConfig>): void;
