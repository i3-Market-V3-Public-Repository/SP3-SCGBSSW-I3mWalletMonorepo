import { DecodedProof, Dict, NrProofPayload, TimestampVerifyOptions } from '../types.js';
export declare function verifyProof<T extends NrProofPayload>(proof: string, expectedPayloadClaims: Partial<T> & {
    iss: T['iss'];
    proofType: T['proofType'];
    exchange: Dict<T['exchange']>;
}, options?: TimestampVerifyOptions): Promise<DecodedProof<T>>;
//# sourceMappingURL=verifyProof.d.ts.map