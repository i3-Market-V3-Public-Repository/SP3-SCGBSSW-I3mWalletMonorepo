/// <reference types="node" />
import type { OpenApiPaths, OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi';
import { EventEmitter } from 'events';
export declare class VaultClient extends EventEmitter {
    timestamp?: number;
    private token?;
    name: string;
    serverUrl: string;
    username: string;
    private password?;
    private keyManager?;
    wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration;
    initialized: Promise<boolean>;
    private es?;
    constructor(serverUrl: string, username: string, password: string, name?: string);
    private init;
    private emitError;
    private getWellKnownCvsConfiguration;
    private initEventSourceClient;
    close(): void;
    getAuthKey(): Promise<string | null>;
    login(): Promise<boolean>;
    logout(): void;
    getRemoteStorageTimestamp(): Promise<number | null>;
    updateStorage(storage: OpenApiPaths.ApiV2Vault.Post.RequestBody, force?: boolean): Promise<boolean>;
    deleteStorage(): Promise<boolean>;
    getServerPublicKey(): Promise<OpenApiComponents.Schemas.JwkEcPublicKey | null>;
}
//# sourceMappingURL=vault-client.d.ts.map