import { JWK, KeyLike } from 'jose';
import { PoO, PoR } from './proofInterfaces';
/**
 * Validate Proof or Request using the Provider Public Key
 */
declare const validatePoR: (publicKey: KeyLike, poR: string, poO: string) => Promise<boolean>;
/**
 * Decode Proof of Reception with Consumer public key
 */
declare const decodePor: (publicKey: KeyLike, poR: string) => Promise<PoR>;
/**
 * Validate Proof or Origin using the Consumer Public Key
 */
declare const validatePoO: (publicKey: KeyLike, poO: string, cipherblock: string) => Promise<boolean>;
/**
 * Decode Proof of Origin with Provider public key
 */
declare const decodePoo: (publicKey: KeyLike, poO: string) => Promise<PoO>;
/**
 * Validate Proof of Publication using the Backplain Public Key
 */
declare const validatePoP: (publicKeyBackplain: KeyLike, publicKeyProvider: KeyLike, poP: string, jwk: JWK, poO: string) => Promise<boolean>;
/**
 * Decrypt the cipherblock received
 */
declare const decryptCipherblock: (chiperblock: string, jwk: JWK) => Promise<string>;
/**
 * Validate the cipherblock
 */
declare const validateCipherblock: (publicKey: KeyLike, chiperblock: string, jwk: JWK, poO: PoO) => Promise<boolean>;
export { validatePoR, validatePoO, validatePoP, decryptCipherblock, validateCipherblock, decodePoo, decodePor };
//# sourceMappingURL=validateProofs.d.ts.map