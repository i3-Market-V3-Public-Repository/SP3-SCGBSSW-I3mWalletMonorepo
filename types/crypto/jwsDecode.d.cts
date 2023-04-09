import { DecodedProof, getFromJws, JWK, ProofPayload } from '../types.js';
export declare function jwsDecode<T extends ProofPayload>(jws: string, publicJwk?: JWK | getFromJws<T>): Promise<DecodedProof<T>>;
//# sourceMappingURL=jwsDecode.d.ts.map