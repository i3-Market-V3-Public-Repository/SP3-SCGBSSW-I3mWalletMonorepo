/// <reference types="node" />
import type { OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi';
import { EventEmitter } from 'node:events';
export declare class VaultClient extends EventEmitter {
    timestamp?: number;
    token?: string;
    name: string;
    serverUrl: string;
    vaultPath: string;
    private es;
    constructor(serverUrl: string, name?: string);
    private initEventSourceClient;
    close(): void;
    login(username: string, authkey: string): Promise<boolean>;
    logout(): void;
    updateStorage(storage: OpenApiPaths.ApiV2Vault.Post.RequestBody, force?: boolean): Promise<boolean>;
    deleteStorage(): Promise<boolean>;
}
//# sourceMappingURL=vault-client.d.ts.map