import { JWK } from 'jose';
import { ProofInputPayload } from './types';
export { JWK };
/**
 * Creates a non-repudiable proof for a given data exchange
 * @param issuer - if the issuer of the proof is the origin 'orig' or the destination 'dest' of the data exchange
 * @param payload - it must contain a 'dataExchange' the issuer 'iss' (either point to the origin 'orig' or the destination 'dest' of the data exchange) of the proof and any specific proof key-values
 * @param privateJwk - The private key in JWK that will sign the proof
 * @returns a proof as a compact JWS formatted JWT string
 */
export declare function createProof(payload: ProofInputPayload, privateJwk: JWK): Promise<string>;
//# sourceMappingURL=createProof.d.ts.map