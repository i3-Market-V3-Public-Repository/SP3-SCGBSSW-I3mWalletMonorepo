/// <reference types="node" />
/// <reference types="node" />
import { BinaryLike, KeyObject } from 'node:crypto';
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
export interface DerivationOptions {
    master: KdfOptions;
    auth: KdfOptions;
    enc: KdfOptions;
}
export declare class KeyManager {
    private _encKey;
    private _authKey;
    derivationOptions: DerivationOptions;
    initialized: Promise<void>;
    constructor(password: BinaryLike, opts: DerivationOptions);
    private init;
    getAuthKey(): Promise<string>;
    getEncKey(): Promise<KeyObject>;
}
export declare function deriveKey(password: BinaryLike, opts: KdfOptions, returnBuffer?: false): Promise<KeyObject>;
export declare function deriveKey(password: BinaryLike, opts: KdfOptions, returnBuffer: true): Promise<Buffer>;
//# sourceMappingURL=key-manager.d.ts.map