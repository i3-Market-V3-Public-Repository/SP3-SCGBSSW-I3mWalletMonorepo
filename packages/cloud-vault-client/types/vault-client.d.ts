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
    private token?;
    name: string;
    serverUrl: string;
    username: string;
    private password?;
    private keyManager?;
    wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration;
    private readonly initialized;
    private es?;
    constructor(serverUrl: string, username: string, password: string, name?: string);
    emit<T extends VaultEventName>(eventName: T, ...args: ArgsForEvent<T>): boolean;
    emit(eventName: string | symbol, ...args: any[]): boolean;
    on<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this;
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    once<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this;
    once(eventName: string | symbol, listener: (...args: any[]) => void): this;
    private init;
    private getWellKnownCvsConfiguration;
    private initEventSourceClient;
    private emitError;
    logout(): void;
    getAuthKey(): Promise<string>;
    login(): Promise<void>;
    getRemoteStorageTimestamp(): Promise<number | null>;
    getStorage(): Promise<VaultStorage>;
    updateStorage(storage: VaultStorage, force?: boolean): Promise<void>;
    deleteStorage(): Promise<void>;
    getServerPublicKey(): Promise<OpenApiComponents.Schemas.JwkEcPublicKey>;
}
export {};
//# sourceMappingURL=vault-client.d.ts.map