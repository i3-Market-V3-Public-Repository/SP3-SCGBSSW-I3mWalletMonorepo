/// <reference types="node" />
/// <reference types="node" />
import type { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi';
import { EventEmitter } from 'events';
export interface VaultStorage {
    storage: Buffer;
    timestamp?: number;
}
export interface VaultEvent {
    name: string;
    description: string;
}
export declare class VaultClient extends EventEmitter {
    timestamp?: number;
    private token?;
    name: string;
    serverUrl: string;
    username: string;
    private password?;
    private keyManager?;
    wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration;
    defaultEvents: {
        connected: string;
        close: string;
        'login-required': string;
        'storage-updated': string;
        'storage-deleted': string;
        conflict: string;
        error: string;
    };
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
    getStorage(): Promise<VaultStorage | null>;
    updateStorage(storage: VaultStorage, force?: boolean): Promise<boolean>;
    deleteStorage(): Promise<boolean>;
    getServerPublicKey(): Promise<OpenApiComponents.Schemas.JwkEcPublicKey | null>;
}
//# sourceMappingURL=vault-client.d.ts.map