export interface ServerConfig {
    addr: string;
    port: number;
    url: string;
}
export declare function checkIfIPv6(str: string): boolean;
export declare const server: ServerConfig;
