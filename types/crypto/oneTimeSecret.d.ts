import { Block, EncryptionAlg } from '../types';
/**
 * Create a JWK random (high entropy) symmetric secret
 *
 * @param encAlg - the encryption algorithm
 * @param secret - and optional seed as Uint8Array or string (hex or base64)
 * @param base64 - if a secret is provided as a string, sets base64 decoding. It supports standard, url-safe base64 with and without padding (autodetected).
 * @returns a promise that resolves to the secret in JWK and raw hex string
 */
export declare function oneTimeSecret(encAlg: EncryptionAlg, secret?: Uint8Array | string, base64?: boolean): Promise<Exclude<Block['secret'], undefined>>;
//# sourceMappingURL=oneTimeSecret.d.ts.map