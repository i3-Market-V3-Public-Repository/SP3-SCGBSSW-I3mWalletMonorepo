import { Block, EncryptionAlg } from './types';
/**
 * Create a random (high entropy) symmetric secret for AES-256-GCM
 *
 * @returns a promise that resolves to the secret in JWK and raw hex string
 */
export declare function oneTimeSecret(encAlg: EncryptionAlg): Promise<Exclude<Block['secret'], undefined>>;
//# sourceMappingURL=oneTimeSecret.d.ts.map