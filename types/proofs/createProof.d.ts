import { JWK, ProofPayload, StoredProof } from '../types';
/**
 * Creates a non-repudiable proof for a given data exchange
 * @param payload - the payload to be added to the proof.
 *                  `payload.iss` must be either the origin 'orig' or the destination 'dest' of the data exchange
 *                  `payload.iat` shall be ommitted since it will be automatically added when signing (`Date.now()`)
 * @param privateJwk - The private key in JWK that will sign the proof
 * @returns a proof as a compact JWS formatted JWT string
 */
export declare function createProof<T extends ProofPayload>(payload: Omit<T, 'iat'>, privateJwk: JWK): Promise<StoredProof<T>>;
//# sourceMappingURL=createProof.d.ts.map