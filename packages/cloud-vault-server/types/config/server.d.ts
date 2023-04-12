export interface ServerConfig {
    id: string;
    addr: string;
    port: number;
    localUrl: string;
    publicUrl: string;
}
export declare function checkIfIPv6(str: string): boolean;
export declare const serverConfig: ServerConfig;
