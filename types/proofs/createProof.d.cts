import { JWK, NrProofPayload, StoredProof } from '../types.js';
export declare function createProof<T extends NrProofPayload>(payload: Omit<T, 'iat'>, privateJwk: JWK): Promise<StoredProof<T>>;
//# sourceMappingURL=createProof.d.ts.map