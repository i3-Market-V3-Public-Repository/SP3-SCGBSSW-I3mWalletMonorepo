/// <reference types="node" />
/// <reference types="node" />
import type { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi';
import { EventEmitter } from 'events';
import type { ArgsForEvent, VaultEventName } from './events';
type CbOnEventFn<T extends VaultEventName> = (...args: ArgsForEvent<T>) => void;
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
    readonly initialized: Promise<void>;
    private keyManager?;
    private es?;
    constructor(serverUrl: string, token?: string, name?: string);
    emit<T extends VaultEventName>(eventName: T, ...args: ArgsForEvent<T>): boolean;
    emit(eventName: string | symbol, ...args: any[]): boolean;
    on<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this;
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    once<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this;
    once(eventName: string | symbol, listener: (...args: any[]) => void): this;
    private init;
    private initEventSourceClient;
    private emitError;
    private initKeyManager;
    logout(): void;
    login(username: string, password: string): Promise<void>;
    getRemoteStorageTimestamp(): Promise<number | null>;
    getStorage(): Promise<VaultStorage>;
    updateStorage(storage: VaultStorage, force?: boolean): Promise<void>;
    deleteStorage(): Promise<void>;
    getServerPublicKey(): Promise<OpenApiComponents.Schemas.JwkEcPublicKey>;
    static getWellKnownCvsConfiguration(serverUrl: string): Promise<OpenApiComponents.Schemas.CvsConfiguration>;
    static computeAuthKey(serverUrl: string, username: string, password: string): Promise<string>;
}
export {};
//# sourceMappingURL=vault-client.d.ts.map