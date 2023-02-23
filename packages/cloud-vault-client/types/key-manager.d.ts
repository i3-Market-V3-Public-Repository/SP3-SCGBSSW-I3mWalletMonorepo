/// <reference types="node" />
/// <reference types="node" />
import { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi';
import { KeyObject } from 'crypto';
import { SecretKey } from './secret-key';
import './scrypt-thread';
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
    derivationOptions: OpenApiComponents.Schemas.VaultConfiguration['key_derivation'];
    initialized: Promise<void>;
    private _initialized;
    constructor(username: string, password: string, opts: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']);
    private init;
    get authKey(): string;
    get encKey(): SecretKey;
}
export declare function deriveKey(password: string, opts: KeyDerivationOptions): Promise<KeyObject>;
export declare function deriveKey(key: KeyObject, opts: KeyDerivationOptions): Promise<KeyObject>;
//# sourceMappingURL=key-manager.d.ts.map