import { CompactDecryptResult } from 'jose';
import { EncryptionAlg, JWK } from '../types';
export declare function jweEncrypt(block: Uint8Array, secretOrPublicKey: JWK, encAlg?: EncryptionAlg): Promise<string>;
export declare function jweDecrypt(jwe: string, secretOrPrivateKey: JWK): Promise<CompactDecryptResult>;
//# sourceMappingURL=jwe.d.ts.map