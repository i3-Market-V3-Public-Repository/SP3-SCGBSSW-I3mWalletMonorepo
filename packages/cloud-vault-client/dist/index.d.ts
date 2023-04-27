/// <reference types="node" />
import { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi';
import { KeyObject } from 'crypto';
import { EventEmitter } from 'events';
import { AxiosResponse } from 'axios';

declare class SecretKey {
    private readonly key;
    readonly alg: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']['enc']['enc_algorithm'];
    constructor(key: KeyObject, alg: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']['enc']['enc_algorithm']);
    encrypt(input: Buffer): Buffer;
    decrypt(input: Buffer): Buffer;
}

interface ScryptOptions {
    N: number;
    r: number;
    p: number;
    maxmem: number;
}
interface KeyDerivationOptions extends OpenApiComponents.Schemas.KeyDerivationOptions {
    salt: Buffer;
}
declare class KeyManager {
    private _encKey;
    private _authKey;
    username: string;
    derivationOptions: OpenApiComponents.Schemas.VaultConfiguration['key_derivation'];
    initialized: Promise<void>;
    private _initialized;
    constructor(username: string, password: string, opts: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']);
    private init;
    get authKey(): string;
    get encKey(): SecretKey;
}
declare function deriveKey(password: string, opts: KeyDerivationOptions): Promise<KeyObject>;
declare function deriveKey(key: KeyObject, opts: KeyDerivationOptions): Promise<KeyObject>;

interface RetryOptions {
    retries: number;
    retryDelay: number;
}
interface CallOptions<T = unknown> {
    bearerToken?: string;
    responseStatus?: number;
    sequential?: boolean;
    beforeRequestFinish?: (data: T) => Promise<void>;
}
declare class Request {
    private readonly axios;
    _defaultCallOptions: CallOptions;
    _defaultUrl?: string;
    private _stop;
    ongoingRequests: {
        [url: string]: Array<Promise<AxiosResponse>>;
    };
    constructor(opts?: {
        retryOptions?: RetryOptions;
        defaultCallOptions?: CallOptions;
        defaultUrl?: string;
    });
    get defaultUrl(): string | undefined;
    set defaultUrl(url: string | undefined);
    get defaultCallOptions(): CallOptions;
    set defaultCallOptions(opts: CallOptions);
    private getAxiosInstance;
    waitForOngoingRequestsToFinsh(url?: string): Promise<void>;
    stop(): Promise<void>;
    private request;
    delete<T>(url: string, options?: CallOptions<T>): Promise<T>;
    delete<T>(options?: CallOptions<T>): Promise<T>;
    get<T>(url: string, options?: CallOptions<T>): Promise<T>;
    get<T>(options?: CallOptions<T>): Promise<T>;
    post<T>(url: string, requestBody: any, options?: CallOptions<T>): Promise<T>;
    post<T>(requestBody: any, options?: CallOptions<T>): Promise<T>;
    put<T>(url: string, requestBody: any, options?: CallOptions<T>): Promise<T>;
    put<T>(requestBody: any, options?: CallOptions<T>): Promise<T>;
}

declare const VAULT_STATE: {
    readonly NOT_INITIALIZED: 0;
    readonly INITIALIZED: 1;
    readonly LOGGED_IN: 2;
    readonly CONNECTED: 3;
};
type VaultState = typeof VAULT_STATE['NOT_INITIALIZED'] | typeof VAULT_STATE['INITIALIZED'] | typeof VAULT_STATE['LOGGED_IN'] | typeof VAULT_STATE['CONNECTED'];

type VaultEvent = {
    'state-changed': [
        state: VaultState
    ];
    'empty-storage': never;
    'storage-updated': [
        timestamp: number
    ];
    'storage-deleted': never;
    'sync-start': [
        startTime: number
    ];
    'sync-stop': [
        startTime: number,
        stopTime: number
    ];
};
type VaultEventName = keyof VaultEvent;
type ArgsForEvent<T extends VaultEventName> = VaultEvent[T];

interface PasswordStrengthOptions {
    minLength?: number;
    uppercase?: boolean;
    lowercase?: boolean;
    numbers?: boolean;
    symbols?: boolean;
    allowedSymbols?: string;
}
declare function passwordCheck(password: string, options?: PasswordStrengthOptions): void;

type CbOnEventFn<T extends VaultEventName> = (...args: ArgsForEvent<T>) => void;
interface VaultStorage {
    storage: Buffer;
    timestamp?: number;
}
interface VaultClientOpts {
    name?: string;
    defaultRetryOptions?: RetryOptions;
    passwordStrengthOptions?: PasswordStrengthOptions;
}
interface LoginOptions {
    username: string;
    password: string;
    timestamp?: number;
}
declare class VaultClient extends EventEmitter {
    timestamp?: number;
    token?: string;
    name: string;
    serverUrl?: string;
    wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration;
    state: Promise<VaultState>;
    private readonly request;
    private keyManager?;
    private es?;
    private switchingState;
    constructor(opts?: VaultClientOpts);
    emit<T extends VaultEventName>(eventName: T, ...args: ArgsForEvent<T>): boolean;
    on<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this;
    once<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this;
    protected switchToState(newState: VaultState, opts?: LoginOptions): Promise<VaultState>;
    private _switchToStatePromise;
    private _switchToState;
    private _initEventSourceClient;
    private _initKeyManager;
    init(serverUrl: string): Promise<string>;
    login(username: string, password: string, timestamp?: number): Promise<void>;
    logout(): Promise<void>;
    close(): Promise<void>;
    getRemoteStorageTimestamp(): Promise<number | null>;
    getStorage(): Promise<VaultStorage>;
    updateStorage(storage: VaultStorage, force?: boolean): Promise<number>;
    deleteStorage(): Promise<void>;
    getRegistrationUrl(username: string, password: string, did: string, passwordStrengthOptions?: PasswordStrengthOptions): Promise<string>;
    private computeAuthKey;
}

type VaultErrorData = {
    'not-initialized': any;
    'http-connection-error': {
        request: {
            method?: string;
            url?: string;
            headers?: {
                [header: string]: string;
            };
            data?: any;
        };
        response?: {
            status?: number;
            headers?: {
                [header: string]: string;
            };
            data?: any;
        };
    };
    'http-request-canceled': {
        request: {
            method?: string;
            url?: string;
            headers?: {
                [header: string]: string;
            };
            data?: any;
        };
    };
    'no-uploaded-storage': any;
    'sse-connection-error': any;
    'quota-exceeded': string;
    conflict: {
        localTimestamp?: number;
        remoteTimestamp?: number;
    };
    unauthorized: any;
    'invalid-credentials': any;
    'weak-password': string;
    'invalid-timestamp': any;
    error: Error;
    unknown: any;
    validation: {
        description?: string;
        data?: any;
    };
};
type VaultErrorName = keyof VaultErrorData;
type DataForError<T extends VaultErrorName> = VaultErrorData[T];
declare class VaultError<T extends VaultErrorName = VaultErrorName> extends Error {
    data: any;
    message: T;
    constructor(message: T, data: DataForError<T>, options?: ErrorOptions);
    static from(error: unknown): VaultError;
}
declare function checkErrorType<T extends VaultErrorName>(err: VaultError, type: T): err is VaultError<T>;

export { CbOnEventFn, DataForError, KeyDerivationOptions, KeyManager, PasswordStrengthOptions, Request, RetryOptions, ScryptOptions, SecretKey, VAULT_STATE, VaultClient, VaultClientOpts, VaultError, VaultErrorData, VaultErrorName, VaultState, VaultStorage, checkErrorType, deriveKey, passwordCheck };
