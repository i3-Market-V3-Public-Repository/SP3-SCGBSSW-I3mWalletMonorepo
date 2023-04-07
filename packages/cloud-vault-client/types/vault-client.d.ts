/// <reference types="node" />
/// <reference types="node" />
import type { OpenApiComponents, OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi';
import { RetryOptions } from './request';
import { EventEmitter } from 'events';
import type { ArgsForEvent, VaultEventName } from './events';
export type CbOnEventFn<T extends VaultEventName> = (...args: ArgsForEvent<T>) => void;
export interface VaultStorage {
    storage: Buffer;
    timestamp?: number;
}
export interface VaultClientOpts {
    name?: string;
    defaultRetryOptions?: RetryOptions;
}
export declare class VaultClient extends EventEmitter {
    timestamp?: number;
    token?: string;
    name: string;
    opts?: VaultClientOpts;
    serverRootUrl: string;
    serverPrefix: string;
    private wellKnownCvsConfigurationPromise?;
    wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration;
    private _state;
    private _initialized;
    private vaultRequest?;
    private keyManager?;
    private es?;
    constructor(serverUrl: string, opts?: VaultClientOpts);
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
    close(): void;
    login(username: string, password: string, timestamp?: number): Promise<void>;
    getRemoteStorageTimestamp(): Promise<number | null>;
    getStorage(): Promise<VaultStorage>;
    updateStorage(storage: VaultStorage, force?: boolean, retryOptions?: RetryOptions): Promise<number>;
    deleteStorage(): Promise<void>;
    getServerPublicKey(): Promise<OpenApiComponents.Schemas.JwkEcPublicKey>;
    static getWellKnownCvsConfiguration(serverUrl: string, opts?: RetryOptions): {
        stop: () => Promise<void>;
        promise: Promise<OpenApiPaths.WellKnownCvsConfiguration.Get.Responses.$200>;
    };
    static computeAuthKey(serverUrl: string, username: string, password: string, retryOptions?: RetryOptions): Promise<string>;
}
//# sourceMappingURL=vault-client.d.ts.map