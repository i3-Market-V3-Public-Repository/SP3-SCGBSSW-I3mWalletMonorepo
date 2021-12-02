import { DataExchange } from './types';
import { CompactDecryptResult, JWK } from 'jose';
export { CompactDecryptResult };
/**
 * Encrypts block to JWE
 *
 * @param exchangeId - the id of the data exchange
 * @param block - the actual block of data
 * @param secret - a one-time secret for encrypting this block
 * @returns a Compact JWE
 */
export declare function jweEncrypt(exchangeId: DataExchange['id'], block: Uint8Array, secret: JWK): Promise<string>;
/**
 * Decrypts jwe
 * @param jwe - a JWE
 * @param secret - a JWK with the secret to decrypt this jwe
 * @returns the plaintext
 */
export declare function jweDecrypt(jwe: string, secret: JWK): Promise<CompactDecryptResult>;
//# sourceMappingURL=jwe.d.ts.map