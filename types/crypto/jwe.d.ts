import { CompactDecryptResult } from 'jose';
import { EncryptionAlg, JWK } from '../types';
export declare function jweEncrypt(block: Uint8Array, secret: JWK, encAlg: EncryptionAlg): Promise<string>;
export declare function jweDecrypt(jwe: string, secret: JWK, encAlg?: EncryptionAlg): Promise<CompactDecryptResult>;
//# sourceMappingURL=jwe.d.ts.map