import { NrpDltAgentDest } from '../dlt/';
import { Block, DataExchange, DataExchangeAgreement, DecodedProof, JWK, JwkPair, PoOPayload, PoPPayload, PoRPayload, StoredProof, TimestampVerifyOptions } from './../types';
export declare class NonRepudiationDest {
    agreement: DataExchangeAgreement;
    exchange?: DataExchange;
    jwkPairDest: JwkPair;
    publicJwkOrig: JWK;
    block: Block;
    dltAgent: NrpDltAgentDest;
    readonly initialized: Promise<boolean>;
    constructor(agreement: DataExchangeAgreement, privateJwk: JWK, dltAgent: NrpDltAgentDest);
    private asyncConstructor;
    verifyPoO(poo: string, cipherblock: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<DecodedProof<PoOPayload>>;
    generatePoR(): Promise<StoredProof<PoRPayload>>;
    verifyPoP(pop: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<DecodedProof<PoPPayload>>;
    getSecretFromLedger(): Promise<{
        hex: string;
        jwk: JWK;
    }>;
    decrypt(): Promise<Uint8Array>;
    generateVerificationRequest(): Promise<string>;
    generateDisputeRequest(): Promise<string>;
}
//# sourceMappingURL=NonRepudiationDest.d.ts.map