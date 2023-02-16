/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
import { EventEmitter } from 'events';
import { BinaryLike, KeyObject } from 'crypto';
import { Store } from '../../app';
/**
 * A class that implements a storage for the wallet in a single file. The server wallet uses a file as storage.
 *
 * `filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)
 *
 * The wallet's storage-file can be encrypted for added security.
 */
export declare class FileStore<T extends Record<string, any> = Record<string, unknown>> extends EventEmitter implements Store<T> {
    filepath: string;
    private key;
    private readonly _password?;
    private _passwordSalt?;
    initialized: Promise<void>;
    defaultModel: T;
    /**
     *
     * @param filepath an absolute path to the file that will be used to store wallet data
     * @param keyObject a key object holding a 32 bytes symmetric key to use for encryption/decryption of the storage
     */
    constructor(filepath: string, keyObject?: KeyObject, defaultModel?: T);
    /**
     *
     * @param filepath an absolute path to the file that will be used to store wallet data
     * @param password if provided a key will be derived from the password and the store file will be encrypted
     *
     * @deprecated you should consider passing a more secure KeyObject derived from your password
     */
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
    has<Key extends 'accounts'>(key: Key): Promise<boolean>;
    delete<Key extends 'accounts'>(key: Key): Promise<void>;
    clear(): Promise<void>;
    getStore(): Promise<T>;
    getPath(): string;
}
export interface ScryptOptions {
    N?: number;
    r?: number;
    p?: number;
    maxmem?: number;
}
export interface KdfOptions {
    alg: 'scrypt';
    derivedKeyLength: number;
    salt: BinaryLike;
    algOptions?: ScryptOptions;
}
export declare function deriveKey(password: BinaryLike, opts: KdfOptions, returnBuffer?: false): Promise<KeyObject>;
export declare function deriveKey(password: BinaryLike, opts: KdfOptions, returnBuffer: true): Promise<Buffer>;
//# sourceMappingURL=file-store.d.ts.map