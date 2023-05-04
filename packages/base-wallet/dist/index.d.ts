/// <reference types="node" />
import { WalletPaths, WalletComponents } from '@i3m/wallet-desktop-openapi/types';
import { VerifiableCredential as VerifiableCredential$1, TAgent, IDIDManager, IKeyManager, IResolver, IMessageHandler, IIdentifier, IMessage, VerifiablePresentation } from '@veramo/core';
import { AbstractIdentifierProvider } from '@veramo/did-manager';
import { ISelectiveDisclosure } from '@veramo/selective-disclosure';
import { ICredentialIssuer } from '@veramo/credential-w3c';
import { EventEmitter } from 'events';
import { KeyObject, BinaryLike } from 'crypto';

interface BaseDialogOptions {
    title?: string;
    message?: string;
    timeout?: number;
    allowCancel?: boolean;
}
interface TextOptions extends BaseDialogOptions {
    hiddenText?: boolean;
    default?: string;
}
interface ConfirmationOptions extends BaseDialogOptions {
    acceptMsg?: string;
    rejectMsg?: string;
}
interface SelectOptions<T> extends BaseDialogOptions {
    freeAnswer?: boolean;
    showInput?: boolean;
    values: T[];
    getText?: (obj: T) => string;
    getContext?: (obj: T) => DialogOptionContext;
}
interface TextFormDescriptor extends TextOptions {
    type: 'text';
}
interface ConfirmationFormDescriptor extends ConfirmationOptions {
    type: 'confirmation';
}
interface SelectFormDescriptor<T> extends SelectOptions<T> {
    type: 'select';
}
type DialogOptionContext = 'success' | 'danger';
type Descriptors<T = any> = TextFormDescriptor | ConfirmationFormDescriptor | SelectFormDescriptor<T>;
type DescriptorsMap<T = any> = {
    [K in keyof Partial<T>]: Descriptors<T[K]>;
};
interface FormOptions<T> extends BaseDialogOptions {
    descriptors: DescriptorsMap<T>;
    order: Array<keyof T>;
}
type DialogResponse<T> = Promise<T | undefined>;
interface Dialog {
    text: (options: TextOptions) => DialogResponse<string>;
    confirmation: (options: ConfirmationOptions) => DialogResponse<boolean>;
    authenticate: () => DialogResponse<boolean>;
    select: <T>(options: SelectOptions<T>) => DialogResponse<T>;
    form: <T>(options: FormOptions<T>) => DialogResponse<T>;
}

declare const _default: {
    encode: (buf: Buffer) => string;
    decode: (str: string) => Buffer;
};
//# sourceMappingURL=base64url.d.ts.map

declare function getCredentialClaims(vc: VerifiableCredential$1): string[];

interface KeyWallet<T extends TypedArray = Uint8Array> {
    createAccountKeyPair: () => Promise<string>;
    getPublicKey: (id: string) => Promise<KeyLike>;
    signDigest: (id: string, message: T) => Promise<T>;
    delete: (id: string) => Promise<boolean>;
    wipe: () => Promise<void>;
}

type PluginMap = IDIDManager & IKeyManager & IResolver & IMessageHandler & ISelectiveDisclosure & ICredentialIssuer;
interface ProviderData {
    network: string;
    rpcUrl?: string | string[];
    web3Provider?: object;
    ttl?: number;
    gas?: number;
    registry?: string;
}
declare const DEFAULT_PROVIDER = "did:ethr:i3m";
declare const DEFAULT_PROVIDERS_DATA: Record<string, ProviderData>;
declare class Veramo<T extends BaseWalletModel = BaseWalletModel> {
    agent: TAgent<PluginMap>;
    providers: Record<string, AbstractIdentifierProvider>;
    defaultKms: string;
    providersData: Record<string, ProviderData>;
    constructor(store: Store<T>, keyWallet: KeyWallet, providersData: Record<string, ProviderData>);
    getProvider(name: string): AbstractIdentifierProvider;
}

declare function verifyDataSharingAgreementSignature(agreement: ContractResource['resource']['dataSharingAgreement'], veramo: Veramo<BaseWalletModel>, signer: 'provider' | 'consumer'): Promise<Error[]>;

declare function didJwtVerify(jwt: string, veramo: Veramo, expectedPayloadClaims?: any): Promise<WalletPaths.DidJwtVerify.Responses.$200>;

interface SecretJwk {
    kid: string;
    kty: string;
    k: string;
}
declare const jwkSecret: (secret?: Buffer) => SecretJwk;
//# sourceMappingURL=generate-secret.d.ts.map

declare function parseAddress(a: string): string;

declare function parseHex(a: string, prefix0x?: boolean): string;

type CanBePromise<T> = Promise<T> | T;
type TypedArray = Int8Array | Uint8Array | Uint8ClampedArray | Int16Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Float64Array | BigInt64Array | BigUint64Array;
type KeyLike = Uint8Array;

interface MultipleExecutionsOptions {
    successRate?: number;
    timeout?: number;
}
type FunctionMap<K extends string> = {
    [P in K]: (...args: any) => any;
};
type ValueOrResolvedValue<T> = T extends Promise<infer R> ? R : T;
type MultipleExecutionsReturn<K extends string, T extends FunctionMap<K>> = ValueOrResolvedValue<ReturnType<T[K]>>;
declare function multipleExecutions<K extends string, T extends FunctionMap<K>>(options: MultipleExecutionsOptions, executors: T[], fnName: K, ...args: any[]): Promise<Array<MultipleExecutionsReturn<K, T>>>;

type Resource$1 = WalletComponents.Schemas.Resource & WalletComponents.Schemas.ResourceId & {
    identity?: WalletComponents.Schemas.ObjectResource['identity'];
} & {
    parentResource?: WalletComponents.Schemas.ObjectResource['parentResource'];
};
type VerifiableCredentialResource = Resource$1 & {
    type: 'VerifiableCredential';
};
type ObjectResource = Resource$1 & {
    type: 'Object';
};
type KeyPairResource = Resource$1 & {
    type: 'KeyPair';
};
type ContractResource = Resource$1 & {
    type: 'Contract';
};
type NonRepudiationProofResource = Resource$1 & {
    type: 'NonRepudiationProof';
};
type DataExchangeResource = Resource$1 & {
    type: 'DataExchange';
};
type VerifiableCredential = WalletComponents.Schemas.VerifiableCredential['resource'];
type KeyPair = WalletComponents.Schemas.KeyPair['resource'];
type Contract = WalletComponents.Schemas.Contract['resource'];
type Object$1 = WalletComponents.Schemas.ObjectResource['resource'];
type Identity = IIdentifier;
interface BaseWalletModel {
    resources: {
        [id: string]: Resource$1;
    };
    identities: {
        [did: string]: Identity;
    };
}
interface Store<T extends Record<string, any> = Record<string, unknown>> {
    get<Key extends keyof T>(key: Key): CanBePromise<T[Key]>;
    get<Key extends keyof T>(key: Key, defaultValue: Required<T>[Key]): CanBePromise<Required<T>[Key]>;
    set(store: Partial<T>): CanBePromise<void>;
    set<Key extends keyof T>(key: Key, value: T[Key]): CanBePromise<void>;
    set(key: string, value: unknown): CanBePromise<void>;
    has<Key extends keyof T>(key: Key): CanBePromise<boolean>;
    has(key: string): CanBePromise<boolean>;
    delete<Key extends keyof T>(key: Key): CanBePromise<void>;
    delete(key: string): CanBePromise<void>;
    clear: () => CanBePromise<void>;
    getStore: () => CanBePromise<T>;
    getPath: () => string;
    on(eventName: 'changed', listener: (changedAt: number) => void): this;
    on(eventName: 'cleared', listener: (changedAt: number) => void): this;
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    emit(eventName: 'changed', changedAt: number): boolean;
    emit(eventName: 'cleared', changedAt: number): boolean;
    emit(eventName: string | symbol, ...args: any[]): boolean;
}

type ToastType = 'info' | 'success' | 'warning' | 'error';
interface ToastOptions {
    message: string;
    type?: ToastType;
    details?: string;
    timeout?: number;
}
interface Toast {
    show: (toast: ToastOptions) => void;
    close: (toastId: string) => void;
}

interface Validation {
    validated: boolean;
    errors: Error[];
}
type Resource = WalletComponents.Schemas.Resource;
type Validator<T extends Resource> = (resource: T, veramo: Veramo) => Promise<Error[]>;
declare class ResourceValidator {
    protected validators: {
        [key: string]: Validator<any> | undefined;
    };
    constructor();
    private initValidators;
    private setValidator;
    validate(resource: Resource, veramo: Veramo): Promise<Validation>;
}

interface WalletFunctionMetadata {
    name: string;
    description?: string;
    call: string;
    scopes?: string[];
}
interface WalletMetadata {
    name: string;
    features: {
        [feature: string]: any;
    };
    functions: WalletFunctionMetadata[];
}

interface Wallet {
    call: (functionMetadata: WalletFunctionMetadata) => Promise<void>;
    getResources: () => Promise<BaseWalletModel['resources']>;
    getIdentities: () => Promise<BaseWalletModel['identities']>;
    deleteResource: (id: string) => Promise<void>;
    deleteIdentity: (did: string) => Promise<void>;
    wipe: () => Promise<void>;
    identityList: (queryParameters: WalletPaths.IdentityList.QueryParameters) => Promise<WalletPaths.IdentityList.Responses.$200>;
    identityCreate: (requestBody: WalletPaths.IdentityCreate.RequestBody) => Promise<WalletPaths.IdentityCreate.Responses.$201>;
    identitySelect: (queryParameters: WalletPaths.IdentitySelect.QueryParameters) => Promise<WalletPaths.IdentitySelect.Responses.$200>;
    identitySign: (pathParameters: WalletPaths.IdentitySign.PathParameters, requestBody: WalletPaths.IdentitySign.RequestBody) => Promise<WalletPaths.IdentitySign.Responses.$200>;
    identityInfo: (pathParameters: WalletPaths.IdentityInfo.PathParameters) => Promise<WalletPaths.IdentityInfo.Responses.$200>;
    identityDeployTransaction: (pathParameters: WalletPaths.IdentityDeployTransaction.PathParameters, requestBody: WalletPaths.IdentityDeployTransaction.RequestBody) => Promise<WalletPaths.IdentityDeployTransaction.Responses.$200>;
    resourceList: (queryParameters: WalletPaths.ResourceList.QueryParameters) => Promise<WalletPaths.ResourceList.Responses.$200>;
    resourceCreate: (requestBody: WalletPaths.ResourceCreate.RequestBody) => Promise<WalletPaths.ResourceCreate.Responses.$201>;
    selectiveDisclosure: (pathParameters: WalletPaths.SelectiveDisclosure.PathParameters) => Promise<WalletPaths.SelectiveDisclosure.Responses.$200>;
    transactionDeploy: (requestBody: WalletPaths.TransactionDeploy.RequestBody) => Promise<WalletPaths.TransactionDeploy.Responses.$200>;
    didJwtVerify: (requestBody: WalletPaths.DidJwtVerify.RequestBody) => Promise<WalletPaths.DidJwtVerify.Responses.$200>;
    providerinfoGet: () => Promise<WalletPaths.ProviderinfoGet.Responses.$200>;
}

interface WalletOptionsCryptoWallet {
    keyWallet: KeyWallet;
}
interface WalletOptionsSettings<T extends BaseWalletModel> {
    dialog: Dialog;
    store: Store<T>;
    toast: Toast;
    provider?: string;
    providersData?: Record<string, ProviderData>;
}
type WalletOptions<T extends BaseWalletModel> = WalletOptionsSettings<T> & WalletOptionsCryptoWallet;

interface SelectIdentityOptions {
    reason?: string;
}
interface TransactionOptions {
    transaction?: string;
    notifyUser?: boolean;
}
type ResourceMap = BaseWalletModel['resources'];
declare class BaseWallet<Options extends WalletOptions<Model>, Model extends BaseWalletModel = BaseWalletModel> implements Wallet {
    dialog: Dialog;
    store: Store<Model>;
    toast: Toast;
    veramo: Veramo<Model>;
    protected keyWallet: KeyWallet;
    protected resourceValidator: ResourceValidator;
    protected provider: string;
    protected providersData: Record<string, ProviderData>;
    protected confirmations: Record<string, boolean>;
    constructor(opts: Options);
    executeTransaction(options?: TransactionOptions): Promise<void>;
    queryBalance(): Promise<void>;
    createTransaction(): Promise<void>;
    wipe(): Promise<void>;
    selectIdentity(options?: SelectIdentityOptions): Promise<Identity>;
    selectCredentialsForSdr(sdrMessage: IMessage): Promise<VerifiablePresentation | undefined>;
    getKeyWallet<T extends KeyWallet>(): T;
    call(functionMetadata: WalletFunctionMetadata): Promise<void>;
    getIdentities(): Promise<BaseWalletModel['identities']>;
    identityList(queryParameters: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200>;
    identityCreate(requestBody: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201>;
    identitySelect(queryParameters: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200>;
    identitySign(pathParameters: WalletPaths.IdentitySign.PathParameters, requestBody: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200>;
    identityInfo(pathParameters: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200>;
    identityDeployTransaction(pathParameters: WalletPaths.IdentityDeployTransaction.PathParameters, requestBody: WalletComponents.Schemas.Transaction): Promise<WalletComponents.Schemas.Receipt>;
    getResources(): Promise<ResourceMap>;
    private getResource;
    private setResource;
    resourceList(query: WalletPaths.ResourceList.QueryParameters): Promise<WalletPaths.ResourceList.Responses.$200>;
    deleteResource(id: string, requestConfirmation?: boolean): Promise<void>;
    deleteIdentity(did: string): Promise<void>;
    resourceCreate(requestBody: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201>;
    selectiveDisclosure(pathParameters: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200>;
    transactionDeploy(requestBody: WalletComponents.Schemas.SignedTransaction): Promise<WalletPaths.TransactionDeploy.Responses.$200>;
    didJwtVerify(requestBody: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200>;
    providerinfoGet(): Promise<WalletPaths.ProviderinfoGet.Responses.$200>;
}

type WalletBuilder<Options extends WalletOptionsSettings<any>> = (opts: Options) => Promise<Wallet>;

interface Values$1 {
    text: string | undefined;
    confirmation: boolean | undefined;
    selectMap: <T>(values: T[]) => T | undefined;
}
declare class TestDialog implements Dialog {
    private readonly valuesStack;
    get values(): Values$1;
    setValues(values: Partial<Values$1>, cb: () => Promise<void>): Promise<void>;
    text(options: TextOptions): DialogResponse<string>;
    confirmation(options: ConfirmationOptions): DialogResponse<boolean>;
    select<T>(options: SelectOptions<T>): DialogResponse<T>;
    authenticate(): DialogResponse<boolean>;
    form<T>(options: FormOptions<T>): DialogResponse<T>;
}

declare class FileStore<T extends Record<string, any> = Record<string, unknown>> extends EventEmitter implements Store<T> {
    filepath: string;
    private key;
    private readonly _password?;
    private _passwordSalt?;
    initialized: Promise<void>;
    defaultModel: T;
    constructor(filepath: string, keyObject?: KeyObject, defaultModel?: T);
    constructor(filepath: string, password?: string, defaultModel?: T);
    on(eventName: 'changed', listener: (changedAt: number) => void): this;
    on(eventName: 'cleared', listener: (changedAt: number) => void): this;
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    emit(eventName: 'changed', changedAt: number): boolean;
    emit(eventName: 'cleared', changedAt: number): boolean;
    emit(eventName: string | symbol, ...args: any[]): boolean;
    private init;
    deriveKey(password: string, salt?: Buffer): Promise<void>;
    private getModel;
    private setModel;
    private encryptModel;
    private decryptModel;
    get(key: any, defaultValue?: any): Promise<any>;
    set(keyOrStore: any, value?: any): Promise<void>;
    has(key: any): Promise<boolean>;
    delete(key: any): Promise<void>;
    clear(): Promise<void>;
    getStore(): Promise<T>;
    getPath(): string;
}
interface ScryptOptions {
    N?: number;
    r?: number;
    p?: number;
    maxmem?: number;
}
interface KdfOptions {
    alg: 'scrypt';
    derivedKeyLength: number;
    salt: BinaryLike;
    algOptions?: ScryptOptions;
}
declare function deriveKey(password: BinaryLike, opts: KdfOptions, returnBuffer?: false): Promise<KeyObject>;
declare function deriveKey(password: BinaryLike, opts: KdfOptions, returnBuffer: true): Promise<Buffer>;

declare class RamStore<T extends Record<string, any> = Record<string, unknown>> extends EventEmitter implements Store<T> {
    protected defaultModel: T;
    model: T;
    constructor(defaultModel: T);
    on(eventName: 'changed', listener: (changedAt: number) => void): this;
    on(eventName: 'cleared', listener: (changedAt: number) => void): this;
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    emit(eventName: 'changed', changedAt: number): boolean;
    emit(eventName: 'cleared', changedAt: number): boolean;
    emit(eventName: string | symbol, ...args: any[]): boolean;
    get(key: any, defaultValue?: any): any;
    set(keyOrStore?: any, value?: any): CanBePromise<void>;
    has(key: string): CanBePromise<boolean>;
    delete(key: string): CanBePromise<void>;
    clear(): CanBePromise<void>;
    getStore(): CanBePromise<T>;
    getPath(): string;
}

declare class TestToast implements Toast {
    show(toast: ToastOptions): void;
    close(toastId: string): void;
}

interface HttpData {
    code?: number;
    status?: number;
}
declare class WalletError extends Error {
    code: number;
    status: number;
    constructor(message: string, httpData?: HttpData);
}

interface Values {
    text: string | undefined;
    confirmation: boolean | undefined;
    selectMap: <T>(values: T[]) => T | undefined;
}
declare class NullDialog implements Dialog {
    private readonly valuesStack;
    get values(): Values;
    setValues(values: Partial<Values>, cb: () => Promise<void>): Promise<void>;
    text(options: TextOptions): DialogResponse<string>;
    confirmation(options: ConfirmationOptions): DialogResponse<boolean>;
    select<T>(options: SelectOptions<T>): DialogResponse<T>;
    authenticate(): DialogResponse<boolean>;
    form<T>(options: FormOptions<T>): DialogResponse<T>;
}

declare class ConsoleToast implements Toast {
    show(toast: ToastOptions): void;
    close(toastId: string): void;
}

export { BaseDialogOptions, BaseWallet, BaseWalletModel, CanBePromise, ConfirmationOptions, ConsoleToast, Contract, ContractResource, DEFAULT_PROVIDER, DEFAULT_PROVIDERS_DATA, DataExchangeResource, Descriptors, DescriptorsMap, Dialog, DialogOptionContext, DialogResponse, FileStore, FormOptions, Identity, KdfOptions, KeyLike, KeyPair, KeyPairResource, KeyWallet, MultipleExecutionsOptions, MultipleExecutionsReturn, NonRepudiationProofResource, NullDialog, Object$1 as Object, ObjectResource, ProviderData, RamStore, Resource$1 as Resource, ScryptOptions, SelectOptions, Store, TestDialog, RamStore as TestStore, TestToast, TextOptions, Toast, ToastOptions, ToastType, TypedArray, Veramo, VerifiableCredential, VerifiableCredentialResource, Wallet, WalletBuilder, WalletError, WalletFunctionMetadata, WalletMetadata, WalletOptions, WalletOptionsCryptoWallet, WalletOptionsSettings, _default as base64url, deriveKey, didJwtVerify, getCredentialClaims, jwkSecret, multipleExecutions, parseAddress, parseHex, verifyDataSharingAgreementSignature };
