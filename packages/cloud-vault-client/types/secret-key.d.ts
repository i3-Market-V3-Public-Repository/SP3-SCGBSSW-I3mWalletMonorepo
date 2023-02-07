/// <reference types="node" />
/// <reference types="node" />
import type { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi';
import { KeyObject } from 'crypto';
export declare class SecretKey {
    private readonly key;
    readonly alg: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']['enc']['enc_algorithm'];
    constructor(key: KeyObject, alg: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']['enc']['enc_algorithm']);
    encrypt(input: Buffer): Buffer;
    decrypt(input: Buffer): Buffer;
}
//# sourceMappingURL=secret-key.d.ts.map