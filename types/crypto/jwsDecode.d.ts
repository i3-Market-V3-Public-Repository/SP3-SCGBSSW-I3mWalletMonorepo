import { ProofPayload, getFromJws, JWK, DecodedProof } from '../types';
export declare function jwsDecode<T extends ProofPayload>(jws: string, publicJwk?: JWK | getFromJws<T>): Promise<DecodedProof<T>>;
//# sourceMappingURL=jwsDecode.d.ts.map