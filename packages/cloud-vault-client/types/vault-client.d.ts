/// <reference types="node" />
import type { OpenApiPaths, OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi';
import { EventEmitter } from 'node:events';
export declare class VaultClient extends EventEmitter {
    timestamp?: number;
    token?: string;
    name: string;
    serverUrl: string;
    vaultPath: string;
    publicKeyPath: string;
    private es?;
    constructor(serverUrl: string, name?: string);
    private emitError;
    private initEventSourceClient;
    close(): void;
    login(username: string, authkey: string): Promise<boolean>;
    logout(): void;
    getRemoteStorageTimestamp(): Promise<number | null>;
    updateStorage(storage: OpenApiPaths.ApiV2Vault.Post.RequestBody, force?: boolean): Promise<boolean>;
    deleteStorage(): Promise<boolean>;
    getServerPublicKey(): Promise<OpenApiComponents.Schemas.JwkEcPublicKey | null>;
}
//# sourceMappingURL=vault-client.d.ts.map