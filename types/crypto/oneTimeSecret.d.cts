import { Block, EncryptionAlg } from '../types.js';
export declare function oneTimeSecret(encAlg: EncryptionAlg, secret?: Uint8Array | string, base64?: boolean): Promise<Exclude<Block['secret'], undefined>>;
//# sourceMappingURL=oneTimeSecret.d.ts.map