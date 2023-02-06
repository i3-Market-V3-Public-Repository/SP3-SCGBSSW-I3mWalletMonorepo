/// <reference types="node" />
/// <reference types="node" />
import { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi';
import { KeyObject } from 'crypto';
export interface ScryptOptions {
    N: number;
    r: number;
    p: number;
    maxmem: number;
}
export interface KeyDerivationOptions extends OpenApiComponents.Schemas.KeyDerivationOptions {
    salt: Buffer;
}
export declare class KeyManager {
    private _encKey;
    private _authKey;
    username: string;
    derivationOptions: OpenApiComponents.Schemas.VaultConfiguration['key-derivation'];
    initialized: Promise<void>;
    constructor(username: string, password: string, opts: OpenApiComponents.Schemas.VaultConfiguration['key-derivation']);
    private init;
    getAuthKey(): Promise<string>;
    getEncKey(): Promise<KeyObject>;
}
export declare function deriveKey(password: string, opts: KeyDerivationOptions): Promise<KeyObject>;
export declare function deriveKey(key: KeyObject, opts: KeyDerivationOptions): Promise<KeyObject>;
//# sourceMappingURL=key-manager.d.ts.map