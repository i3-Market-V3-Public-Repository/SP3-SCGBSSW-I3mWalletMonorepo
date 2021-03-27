import { KeyLike, JWK } from 'jose/jwk/from_key_like';
import { account } from './proofInterfaces';
/**
 * Create Proof of Origin and sign with Provider private key
 */
declare const createPoO: (privateKey: KeyLike, block: ArrayBufferLike | string, providerId: string, consumerId: string, exchangeId: number, blockId: number, jwk: JWK) => Promise<any>;
/**
 * Create random (high entropy)\none time symmetric JWK secret
 */
declare const createJwk: () => Promise<JWK>;
/**
 * Sign a proof with private key
 */
declare const signProof: (privateKey: KeyLike, proof: any) => Promise<string>;
/**
 * Create Proof of Receipt and sign with Consumer private key
 */
declare const createPoR: (privateKey: KeyLike, poO: string, providerId: string, consumerId: string, exchangeId: number) => Promise<string>;
/**
 *
 * Prepare block to be send to the Backplain API
 */
declare const createBlockchainProof: (publicKey: KeyLike, poO: string, poR: string, jwk: JWK) => Promise<account>;
export { createJwk, createPoO, signProof, createPoR, createBlockchainProof };
//# sourceMappingURL=createProofs.d.ts.map