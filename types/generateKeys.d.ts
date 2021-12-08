import { JwkPair, SigningAlg } from './types';
/**
 * Generates a pair of JWK signing/verification keys
 *
 * @param alg - the signing algorithm to use
 * @param privateKey - an optional private key as a Uint8Array, or a string (hex or base64)
 * @param base - only used when privateKey is a string. Set to true if the privateKey is base64 encoded (standard base64, url-safe bas64 with and without padding are supported)
 * @returns
 */
export declare function generateKeys(alg: SigningAlg, privateKey?: Uint8Array | string, base64?: boolean): Promise<JwkPair>;
//# sourceMappingURL=generateKeys.d.ts.map