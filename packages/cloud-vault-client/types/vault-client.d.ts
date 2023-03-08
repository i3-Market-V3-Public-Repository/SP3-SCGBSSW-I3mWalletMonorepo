/// <reference types="node" />
/// <reference types="node" />
import type { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi';
import { EventEmitter } from 'events';
import type { ArgsForEvent, VaultEventName } from './events';
export type CbOnEventFn<T extends VaultEventName> = (...args: ArgsForEvent<T>) => void;
export interface VaultStorage {
    storage: Buffer;
    timestamp?: number;
}
export declare class VaultClient extends EventEmitter {
    timestamp?: number;
    token?: string;
    name: string;
    serverUrl: string;
    wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration;
    private _state;
    private _initialized;
    private _uploading;
    private keyManager?;
    private es?;
    constructor(serverUrl: string, name?: string);
    get initialized(): Promise<void>;
    get state(): typeof this._state;
    set state(newState: typeof this._state);
    emit<T extends VaultEventName>(eventName: T, ...args: ArgsForEvent<T>): boolean;
    on<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this;
    once<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this;
    private init;
    private initEventSourceClient;
    private initKeyManager;
    logout(): void;
    login(username: string, password: string, timestamp?: number): Promise<void>;
    getRemoteStorageTimestamp(): Promise<number | null>;
    getStorage(): Promise<VaultStorage>;
    private _updateStorage;
    updateStorage(storage: VaultStorage, force?: boolean): Promise<number>;
    deleteStorage(): Promise<void>;
    getServerPublicKey(): Promise<OpenApiComponents.Schemas.JwkEcPublicKey>;
    static getWellKnownCvsConfiguration(serverUrl: string): Promise<OpenApiComponents.Schemas.CvsConfiguration>;
    static computeAuthKey(serverUrl: string, username: string, password: string): Promise<string>;
}
//# sourceMappingURL=vault-client.d.ts.map